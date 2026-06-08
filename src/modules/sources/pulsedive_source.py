"""Pulsedive source adapter for threat intelligence."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class PulsediveSource:
    """Scan Pulsedive for threat intelligence on IPs and domains."""

    BASE_URL = "https://pulsedive.com/api"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 1.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("PULSEDIVE_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        leaks: list[RawLeak] = []
        params = {"indicator": address}
        if self.api_key:
            params["key"] = self.api_key
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/info.php",
                    params=params,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    leaks.append(
                        RawLeak(
                            text=f"Indicator: {address}\nRisk: {data.get('risk', 'unknown')}\nThreats: {data.get('threats', [])}",
                            source_name="pulsedive",
                            source_url=f"https://pulsedive.com/indicator/?iid={address}",
                        )
                    )
            except Exception as exc:
                logger.debug("Pulsedive error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
