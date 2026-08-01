"""Mempool.space source adapter — keyless Bitcoin chain intelligence.

Reverse-engineered / keyless public endpoint (no API key required):
``https://mempool.space/api/address/<address>``

Exposes address summary (balance, tx counts, first/last seen) and recent
transactions — a keyless RE fallback for crypto tracing workflows.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000
_MAX_TXS = 10


class MempoolSource:
    """Keyless Bitcoin address intelligence via mempool.space."""

    BASE_URL = "https://mempool.space/api"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: no global feed; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Return address summary + recent transactions for a BTC address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{self.BASE_URL}/address/{address}")
                if resp.status_code == 200:
                    data = resp.json()
                    chain = data.get("chain_stats") or {}
                    mempool = data.get("mempool_stats") or {}
                    summary = (
                        f"Address {address} — funded {chain.get('funded_txo_sum', 0)} sats, "
                        f"spent {chain.get('spent_txo_sum', 0)} sats, "
                        f"{chain.get('tx_count', 0)} confirmed txs"
                    )
                    leaks.append(
                        RawLeak(
                            text=summary[:_MAX_TEXT],
                            source_name="mempool",
                            source_url=f"https://mempool.space/address/{address}",
                        )
                    )
                    if chain.get("funded_txo_count"):
                        leaks.append(
                            RawLeak(
                                text=f"Funded UTXOs: {chain['funded_txo_count']}"[:_MAX_TEXT],
                                source_name="mempool",
                                source_url=f"https://mempool.space/address/{address}",
                            )
                        )
                    if mempool.get("tx_count"):
                        leaks.append(
                            RawLeak(
                                text=f"Unconfirmed txs: {mempool['tx_count']}"[:_MAX_TEXT],
                                source_name="mempool",
                                source_url=f"https://mempool.space/address/{address}",
                            )
                        )
            except Exception as exc:
                logger.debug("mempool summary error for %s: %s", address, exc)

            try:
                await self._rate_limit()
                txs_resp = await client.get(f"{self.BASE_URL}/address/{address}/txs")
                if txs_resp.status_code == 200:
                    for tx in (txs_resp.json() or [])[:_MAX_TXS]:
                        txid = tx.get("txid", "")
                        value = sum((vin.get("prevout") or {}).get("value", 0) for vin in tx.get("vin") or [])
                        text = f"TX {txid} ({value} sats in)"[:_MAX_TEXT]
                        leaks.append(
                            RawLeak(
                                text=text,
                                source_name="mempool",
                                source_url=f"https://mempool.space/tx/{txid}",
                            )
                        )
            except Exception as exc:
                logger.debug("mempool txs error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
