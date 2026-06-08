"""GreyNoise source adapter for IP intelligence."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class GreyNoiseSource:
    """Scan GreyNoise for IP reputation and intelligence."""

    BASE_URL = "https://api.greynoise.io/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 1.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("GREYNOISE_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        if not self.api_key:
            logger.debug("GreyNoise: no API key configured, skipping")
            return []
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        if not self.api_key:
            return []
        leaks: list[RawLeak] = []
        headers = {"key": self.api_key}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/context/{address}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    leaks.append(
                        RawLeak(
                            text=f"IP: {address}\nNoise: {data.get('noise', False)}\nClassification: {data.get('classification', 'unknown')}",
                            source_name="greynoise",
                            source_url=f"https://viz.greynoise.io/ip/{address}",
                        )
                    )
            except Exception as exc:
                logger.debug("GreyNoise error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
