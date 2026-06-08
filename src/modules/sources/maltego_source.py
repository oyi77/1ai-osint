"""Maltego source adapter for OSINT graph analysis."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class MaltegoSource:
    """Use Maltego Transform Hub for OSINT data gathering."""

    BASE_URL = "https://transforms.maltego.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Maltego requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search for OSINT data using public Maltego transforms."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                # Use public Shodan transform as proxy
                resp = await client.get(
                    f"{self.BASE_URL}/api/v1/search",
                    params={"query": address},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    leaks.append(
                        RawLeak(
                            text=str(data)[:10000],
                            source_name="maltego",
                            source_url=f"https://maltego.com/search?q={address}",
                        )
                    )
            except Exception as exc:
                logger.debug("Maltego error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
