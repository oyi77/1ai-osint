"""Scanner coordinator for cross-tier resource sharing.

Provides a shared coordinator that all scanner tiers (random, leak, smart)
can use for:
- Global API concurrency limiting via asyncio.Semaphore
- Per-chain endpoint rotation via EndpointRotator
- Cross-tier mnemonic and address deduplication (in-memory + persistent SQLite)
- Shared httpx.AsyncClient with connection pooling
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sqlite3

import httpx

from src.modules.crypto.balance.api_rotation import ENDPOINT_REGISTRY, EndpointRotator
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig, ChainType
from src.modules.crypto.balance.checker import BalanceResult, check_balance

logger = logging.getLogger(__name__)

_DEDUP_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scanned_mnemonics (
    mnemonic_hash TEXT PRIMARY KEY,
    source TEXT,
    scanned_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scanned_mnemonics_hash ON scanned_mnemonics(mnemonic_hash);
CREATE TABLE IF NOT EXISTS scanned_keys (
    key_hash TEXT PRIMARY KEY,
    key_type TEXT,
    source TEXT,
    scanned_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scanned_keys_hash ON scanned_keys(key_hash);
"""


class ScannerCoordinator:
    """Shared coordinator for all scanner tiers.

    Enforces global API concurrency, manages per-chain endpoint rotation,
    deduplicates mnemonics and addresses across tiers, and provides a
    shared HTTP client.

    Example::

        coordinator = ScannerCoordinator()
        await coordinator.start()
        result = await coordinator.check_balance(address, chain_cfg, derivation_path)
        await coordinator.stop()
    """

    def __init__(
        self,
        api_concurrency: int = 50,
        chains: list[ChainConfig] | None = None,
        db_path: str = "wallet_hits.db",
    ):
        self._api_semaphore = asyncio.Semaphore(api_concurrency)
        self._chains = chains or list(ALL_CHAINS)
        self._rotators: dict[str, EndpointRotator] = {}
        self._seen_mnemonics: set[str] = set()
        self._seen_keys: set[str] = set()
        self._seen_addresses: set[str] = set()
        self._client: httpx.AsyncClient | None = None
        self._db_path = db_path
        self._db: sqlite3.Connection | None = None

        for chain in self._chains:
            endpoints = ENDPOINT_REGISTRY.get(chain.coin_id, [])
            if endpoints:
                self._rotators[chain.coin_id] = EndpointRotator(endpoints)

    async def start(self) -> None:
        """Initialize the shared HTTP client and persistent dedup database."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=50),
        )
        try:
            self._db = sqlite3.connect(self._db_path)
            self._db.execute(_DEDUP_TABLE_SQL)
            self._db.commit()
            rows = self._db.execute("SELECT mnemonic_hash FROM scanned_mnemonics").fetchall()
            self._seen_mnemonics = {r[0] for r in rows}
            logger.info(
                "ScannerCoordinator started: loaded %d scanned mnemonics from persistent dedup",
                len(self._seen_mnemonics),
            )
        except Exception as e:
            logger.debug("Could not load persistent dedup: %s", e)

    async def stop(self) -> None:
        """Close the shared HTTP client and database connection."""
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._db:
            self._db.close()
            self._db = None

    async def check_balance(
        self,
        address: str,
        chain: ChainConfig,
        derivation_path: str = "",
    ) -> BalanceResult:
        """Check balance with semaphore-controlled concurrency and endpoint rotation.

        Args:
            address: Wallet address to check.
            chain: Chain configuration.
            derivation_path: Derivation path for metadata.

        Returns:
            BalanceResult with balance information.

        """
        import copy

        rotator = self._rotators.get(chain.coin_id)
        rotated_cfg = copy.copy(chain)
        used_url = ""
        if rotator:
            url = rotator.next()
            if chain.chain_type == ChainType.BITCOIN:
                rotated_cfg.api_url = url
            else:
                rotated_cfg.rpc_url = url
            used_url = rotated_cfg.api_url or rotated_cfg.rpc_url or ""

        async with self._api_semaphore:
            try:
                result = await check_balance(address, rotated_cfg, derivation_path, client=self._client)
                if result.error:
                    if rotator:
                        rotator.report_failure(used_url)
                else:
                    if rotator:
                        rotator.report_success(used_url)
                return result
            except Exception as e:
                if rotator:
                    rotator.report_failure(used_url)
                logger.debug("Balance check error for %s on %s: %s", address[:10], chain.name, e)
                return BalanceResult(
                    address=address,
                    chain=chain.name,
                    symbol=chain.symbol,
                    balance=0.0,
                    balance_raw=0,
                    usd_price=0.0,
                    usd_value=0.0,
                    derivation_path=derivation_path,
                    error=str(e),
                )

    @staticmethod
    def hash_mnemonic(mnemonic: str) -> str:
        """SHA-256 hash of a mnemonic for dedup storage."""
        return hashlib.sha256(mnemonic.strip().encode("utf-8")).hexdigest()

    def is_mnemonic_seen(self, mnemonic: str) -> bool:
        """Check if a mnemonic has already been processed (any tier)."""
        h = self.hash_mnemonic(mnemonic)
        return h in self._seen_mnemonics

    def mark_mnemonic_seen(self, mnemonic: str, source: str = "unknown") -> None:
        """Mark a mnemonic as processed (in-memory + persistent SQLite).

        Args:
            mnemonic: The mnemonic phrase.
            source: Which tier scanned it ("random", "leak", "smart").

        """
        h = self.hash_mnemonic(mnemonic)
        self._seen_mnemonics.add(h)
        if self._db:
            try:
                self._db.execute(
                    "INSERT OR IGNORE INTO scanned_mnemonics (mnemonic_hash, source) VALUES (?, ?)",
                    (h, source),
                )
                self._db.commit()
            except Exception as e:
                logger.debug("Failed to persist scanned mnemonic: %s", e)

    @staticmethod
    def hash_key(key: str) -> str:
        """SHA-256 hash of a private key for dedup storage."""
        return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()

    def is_key_seen(self, key: str) -> bool:
        """Check if a private key has already been processed."""
        h = self.hash_key(key)
        return h in self._seen_keys

    def mark_key_seen(self, key: str, key_type: str = "unknown", source: str = "unknown") -> None:
        """Mark a private key as processed (in-memory + persistent SQLite)."""
        h = self.hash_key(key)
        self._seen_keys.add(h)
        if self._db:
            try:
                self._db.execute(
                    "INSERT OR IGNORE INTO scanned_keys (key_hash, key_type, source) VALUES (?, ?, ?)",
                    (h, key_type, source),
                )
                self._db.commit()
            except Exception as e:
                logger.debug("Failed to persist scanned key: %s", e)

    def is_address_seen(self, address: str) -> bool:
        """Check if an address has already been checked."""
        return address in self._seen_addresses

    def mark_address_seen(self, address: str) -> None:
        """Mark an address as checked."""
        self._seen_addresses.add(address)

    def filter_new_addresses(self, addresses: list) -> list:
        """Filter out already-seen addresses and mark new ones as seen.

        Args:
            addresses: List of DerivedAddress objects.

        Returns:
            List of addresses not yet seen.

        """
        new = []
        for addr in addresses:
            if addr.address not in self._seen_addresses:
                self._seen_addresses.add(addr.address)
                new.append(addr)
        return new
