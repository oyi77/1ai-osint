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

from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum

from src.modules.crypto.balance.api_rotation import ENDPOINT_REGISTRY, EndpointRotator
from src.modules.crypto.balance.checker import check_balance, get_usd_prices
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig, ChainType
from src.modules.crypto.balance.deriver import (
    DerivedAddress,
    derive_from_mnemonic,
    is_valid_mnemonic,
)
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)


@dataclass
class ScannerStats:
    """Runtime statistics for the scanner."""
    mnemonics_generated: int = 0
    addresses_checked: int = 0
    hits_found: int = 0
    api_errors: int = 0
    start_time: float = field(default_factory=time.monotonic)

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
        api_concurrency: int = 5,
        chains: Optional[list[ChainConfig]] = None,
        hit_logger: Optional[HitLogger] = None,
    ):
        self.workers = workers
        self.chains = chains or list(ALL_CHAINS)
        self.hit_logger = hit_logger
        self._api_semaphore = asyncio.Semaphore(api_concurrency)
        self._shutdown = False
        self._stats = ScannerStats()
        # Deduplication: track seen mnemonics and addresses
        self._seen_mnemonics: set[str] = set()
        self._seen_addresses: set[str] = set()
        # Per-chain endpoint rotators
        self._rotators: dict[str, EndpointRotator] = {}
        for chain in self.chains:
            endpoints = ENDPOINT_REGISTRY.get(chain.coin_id, [])
            if endpoints:
                self._rotators[chain.coin_id] = EndpointRotator(endpoints)

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
        self._stats = ScannerStats()
        self._shutdown = False

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

        logger.info(
            "Scanner finished: %d mnemonics, %.1f/sec, %d hits, %d errors",
            self._stats.mnemonics_generated,
            self._stats.mnemonics_per_sec,
            self._stats.hits_found,
            self._stats.api_errors,
        )

        return self._stats

    async def _worker(self, worker_id: int, stop_event: asyncio.Event) -> None:
        """Single scanner worker. Generates and checks one mnemonic at a time."""
        while not stop_event.is_set() and not self._shutdown:
            try:
                # 1. Generate random mnemonic
                mnemonic = self._generate_mnemonic()

                # Dedup: skip already-seen mnemonics
                if mnemonic in self._seen_mnemonics:
                    continue
                self._seen_mnemonics.add(mnemonic)

                # 2. Derive addresses (CPU-bound — must use executor)
                loop = asyncio.get_running_loop()
                addresses = await loop.run_in_executor(
                    None,
                    derive_from_mnemonic,
                    mnemonic,
                    self.chains,
                )
                self._stats.mnemonics_generated += 1

                if not addresses:
                    continue

                # Dedup: filter out already-seen addresses
                new_addresses = []
                for addr in addresses:
                    if addr.address not in self._seen_addresses:
                        self._seen_addresses.add(addr.address)
                        new_addresses.append(addr)
                if not new_addresses:
                    continue
                addresses = new_addresses

                # 3. Check balances with semaphore-controlled concurrency
                balance_results = await self._check_balances(addresses)
                self._stats.addresses_checked += len(addresses)

                # 4. Log hits (addresses with balance > 0)
                for addr, balance_result in zip(addresses, balance_results):
                    if balance_result is not None and balance_result.balance > 0:
                        self._stats.hits_found += 1
                        if self.hit_logger:
                            # SECURITY: Strip private_key_hex before logging
                            mnemonic_hash = HitLogger.hash_mnemonic(mnemonic)
                            await self.hit_logger.log_hit(
                                address=addr.address,
                                chain=addr.chain,
                                balance=balance_result.balance,
                                usd_value=balance_result.usd_value,
                                mnemonic_hash=mnemonic_hash,
                                derivation_path=addr.derivation_path,
                                source="random_scan",
                            )

                # 5. Yield to event loop (prevents spin-lock in mocked tests)
                await asyncio.sleep(0)

                # 6. Progress reporting (every 100 mnemonics)
                if self._stats.mnemonics_generated % 100 == 0:
                    logger.info(
                        "Progress: %d mnemonics, %.1f/sec, %d hits, %d errors",
                        self._stats.mnemonics_generated,
                        self._stats.mnemonics_per_sec,
                        self._stats.hits_found,
                        self._stats.api_errors,
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                self._stats.api_errors += 1
                logger.error("Worker %d error: %s", worker_id, e)
                # Brief pause on repeated errors to avoid tight error loops
                await asyncio.sleep(0.1)

    async def _check_balances(
        self, addresses: list[DerivedAddress]
    ) -> list:
        """Check balances for a list of addresses with semaphore control and endpoint rotation."""
        results: list[Optional[object]] = [None] * len(addresses)

        def _rotate_chain(chain_cfg: ChainConfig) -> ChainConfig:
            """Create a copy of chain config with the next rotated endpoint."""
            rotator = self._rotators.get(chain_cfg.coin_id)
            if rotator is None:
                return chain_cfg
            url = rotator.next()
            # Create a copy with the rotated URL
            import copy
            rotated = copy.copy(chain_cfg)
            if chain_cfg.chain_type == ChainType.BITCOIN:
                rotated.api_url = url
            else:
                rotated.rpc_url = url
            return rotated

        async def _check_one(idx: int, addr: DerivedAddress):
            async with self._api_semaphore:
                try:
                    chain_cfg = _find_chain(addr.chain, self.chains)
                    if chain_cfg is None:
                        return
                    rotated_cfg = _rotate_chain(chain_cfg)
                    used_url = rotated_cfg.api_url or rotated_cfg.rpc_url or ""
                    # Rate limit: per-chain delay to avoid 429s
                    # BTC has fewer endpoints and stricter limits
                    delay = 1.0 if chain_cfg.chain_type == ChainType.BITCOIN else 0.2
                    await asyncio.sleep(delay)
                    result = await check_balance(addr.address, rotated_cfg, addr.derivation_path)
                    rotator = self._rotators.get(chain_cfg.coin_id)
                    if rotator:
                        if result.error:
                            self._stats.api_errors += 1
                            rotator.report_failure(used_url)
                        else:
                            rotator.report_success(used_url)
                    results[idx] = result
                except Exception as e:
                    self._stats.api_errors += 1
                    logger.debug("Balance check error for %s: %s", addr.address, e)

        await asyncio.gather(
            *(_check_one(i, a) for i, a in enumerate(addresses)),
            return_exceptions=True,
        )
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
