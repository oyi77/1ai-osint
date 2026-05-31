"""URLhaus source adapter for malware URL intelligence."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class URLhausSource:
    """Query URLhaus for malware URL intelligence."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """URLhaus requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search URLhaus for malware URLs."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    f"{self.BASE_URL}/host/",
                    data={"host": address},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "ok":
                        for url_entry in data.get("urls", []):
                            leaks.append(RawLeak(
                                text=f"URL: {url_entry.get('url', '')}\n"
                                     f"Status: {url_entry.get('url_status', '')}\n"
                                     f"Threat: {url_entry.get('threat', '')}\n"
                                     f"Tags: {url_entry.get('tags', [])}",
                                source_name="urlhaus",
                                source_url=f"https://urlhaus.abuse.ch/host/{address}/",
                            ))
            except Exception as exc:
                logger.debug("URLhaus error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
