"""WiGLE source adapter for wireless network intelligence."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class WiGLESource:
    """Scan WiGLE for wireless network data."""

    BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(self, api_key: Optional[str] = None, request_delay: float = 1.0, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("WIGLE_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        if not self.api_key:
            return []
        leaks: list[RawLeak] = []
        import base64
        auth = base64.b64encode(self.api_key.encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/network/search",
                    params={"ssid": address},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("results", []):
                        leaks.append(RawLeak(
                            text=f"SSID: {entry.get('ssid', '')}\nBSSID: {entry.get('netid', '')}\nChannel: {entry.get('channel', '')}",
                            source_name="wigle",
                            source_url=f"https://wigle.net/search?ssid={address}",
                        ))
            except Exception as exc:
                logger.debug("WiGLE error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
