"""AlienVault OTX source adapter for threat intelligence."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class OTXSource:
    """Query AlienVault OTX for threat intelligence and IoCs."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("OTX_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """OTX requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search OTX for threat intelligence on a domain/IP."""
        if not self.api_key:
            logger.debug("OTX: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"X-OTX-API-KEY": self.api_key}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/indicators/domain/{address}/general",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    leaks.append(
                        RawLeak(
                            text=str(data)[:10000],
                            source_name="otx",
                            source_url=f"https://otx.alienvault.com/indicator/domain/{address}",
                        )
                    )
            except Exception as exc:
                logger.debug("OTX error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
