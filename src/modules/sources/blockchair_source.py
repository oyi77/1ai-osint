"""Blockchair source adapter for multi-chain blockchain analysis."""

from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class BlockchairSource:
    """Query Blockchair for multi-chain blockchain data."""

    BASE_URL = "https://api.blockchair.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 15.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Blockchair requires an address target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Blockchair for address across multiple chains."""
        leaks: list[RawLeak] = []
        chains = ["bitcoin", "ethereum", "bitcoin-cash", "litecoin"]

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for chain in chains:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/{chain}/dashboards/address/{address}",
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        addr_data = data.get("data", {}).get(address.lower(), {})
                        if addr_data:
                            balance = addr_data.get("address", {}).get("balance", 0)
                            tx_count = addr_data.get("address", {}).get(
                                "transaction_count", 0
                            )
                            leaks.append(
                                RawLeak(
                                    text=f"Chain: {chain}\nAddress: {address}\nBalance: {balance}\nTransactions: {tx_count}",
                                    source_name=f"blockchair_{chain}",
                                    source_url=f"https://blockchair.com/{chain}/address/{address}",
                                )
                            )
                except Exception as exc:
                    logger.debug("Blockchair %s error: %s", chain, exc)

        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
