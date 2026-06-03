"""WhatsMyName source adapter for username enumeration."""

from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class WhatsMyNameSource:
    """Use WhatsMyName web app for username enumeration across 600+ sites."""

    BASE_URL = "https://whatsmyname.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """WhatsMyName requires a username target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Check username across 600+ sites using WhatsMyName."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/search",
                    params={"q": address},
                )
                if resp.status_code == 200:
                    text = resp.text
                    if address.lower() in text.lower():
                        leaks.append(
                            RawLeak(
                                text=f"Username '{address}' found on WhatsMyName results page",
                                source_name="whatsmyname",
                                source_url=f"{self.BASE_URL}/search?q={address}",
                            )
                        )
            except Exception as exc:
                logger.debug("WhatsMyName error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
