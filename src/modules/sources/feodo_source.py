"""Feodo Tracker source adapter for botnet C2 intelligence."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class FeodoSource:
    """Query Feodo Tracker for botnet command and control servers."""

    BASE_URL = "https://feodotracker.abuse.ch/downloads"

    def __init__(self, request_delay: float = 2.0, timeout: float = 15.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch Feodo Tracker IP blocklist."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{self.BASE_URL}/ipblocklist_recommended.txt")
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            leaks.append(RawLeak(
                                text=f"C2 IP: {line}",
                                source_name="feodo",
                                source_url=f"https://feodotracker.abuse.ch/browse/ip/{line}/",
                            ))
            except Exception as exc:
                logger.debug("Feodo Tracker error: %s", exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Feodo Tracker for a specific IP."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{self.BASE_URL}/ipblocklist_recommended.txt")
                if resp.status_code == 200:
                    if address in resp.text:
                        leaks.append(RawLeak(
                            text=f"C2 IP found: {address}",
                            source_name="feodo",
                            source_url=f"https://feodotracker.abuse.ch/browse/ip/{address}/",
                        ))
            except Exception as exc:
                logger.debug("Feodo Tracker search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
