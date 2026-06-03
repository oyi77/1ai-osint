"""URLhaus source adapter for malicious URL intelligence."""

from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class URLhausSource:
    """Scan URLhaus for malicious URLs and payloads."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, request_delay: float = 1.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    f"{self.BASE_URL}/urls/recent/",
                    data={"limit": 100},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("urls", []):
                        url = entry.get("url", "")
                        if url:
                            leaks.append(
                                RawLeak(
                                    text=f"URL: {url}\nThreat: {entry.get('threat', '')}\nTags: {entry.get('tags', [])}",
                                    source_name="urlhaus",
                                    source_url=url,
                                )
                            )
            except Exception as exc:
                logger.debug("URLhaus error: %s", exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    f"{self.BASE_URL}/host/",
                    data={"host": address},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("urls", []):
                        url = entry.get("url", "")
                        if url:
                            leaks.append(
                                RawLeak(
                                    text=f"URL: {url}\nThreat: {entry.get('threat', '')}\nTags: {entry.get('tags', [])}",
                                    source_name="urlhaus",
                                    source_url=url,
                                )
                            )
            except Exception as exc:
                logger.debug("URLhaus search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
