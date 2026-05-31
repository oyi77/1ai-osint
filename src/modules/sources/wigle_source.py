"""WiGLE source adapter for wireless network discovery."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class WigleSource:
    """Query WiGLE for wireless network information."""

    BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(self, api_key: Optional[str] = None, request_delay: float = 2.0, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("WIGLE_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """WiGLE requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search WiGLE for wireless networks."""
        if not self.api_key:
            logger.debug("WiGLE: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        # WiGLE uses Basic auth with API name:token
        auth = httpx.BasicAuth(self.api_key, "")
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/network/search",
                    params={"ssid": address},
                    auth=auth,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for net in data.get("results", []):
                        leaks.append(RawLeak(
                            text=f"SSID: {net.get('ssid', '')}\n"
                                 f"BSSID: {net.get('netid', '')}\n"
                                 f"Encryption: {net.get('encryption', '')}\n"
                                 f"City: {net.get('city', '')}",
                            source_name="wigle",
                            source_url=f"https://wigle.net/search?ssid={address}",
                        ))
            except Exception as exc:
                logger.debug("WiGLE error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
