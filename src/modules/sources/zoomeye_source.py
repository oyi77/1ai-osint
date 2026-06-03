"""ZoomEye source adapter for exposed service discovery."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class ZoomEyeSource:
    """Query ZoomEye for exposed services and devices."""

    BASE_URL = "https://api.zoomeye.org"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("ZOOMEYE_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """ZoomEye requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search ZoomEye for exposed services."""
        if not self.api_key:
            logger.debug("ZoomEye: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"Authorization": f"JWT {self.api_key}"}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/host/search",
                    params={"query": address},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for match in data.get("matches", []):
                        banner = match.get("description", "")
                        if banner:
                            leaks.append(
                                RawLeak(
                                    text=banner[:10000],
                                    source_name="zoomeye",
                                    source_url=f"https://www.zoomeye.org/searchResult?q={address}",
                                )
                            )
            except Exception as exc:
                logger.debug("ZoomEye error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
