"""Snusbase source adapter for breach data lookup."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class SnusbaseSource:
    """Query Snusbase for breach data and leaked credentials."""

    BASE_URL = "https://api.snusbase.com/v3/search"

    def __init__(self, api_key: Optional[str] = None, request_delay: float = 2.0, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("SNUSBASE_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Snusbase requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Snusbase for breached credentials."""
        if not self.api_key:
            logger.debug("Snusbase: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"Authorization": self.api_key}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    self.BASE_URL,
                    json={"term": address, "type": "auto"},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("result", {})
                    for table, entries in results.items():
                        if isinstance(entries, list):
                            for entry in entries:
                                leaks.append(RawLeak(
                                    text=f"Table: {table}\n{str(entry)[:5000]}",
                                    source_name="snusbase",
                                    source_url=f"https://snusbase.com/search?q={address}",
                                ))
            except Exception as exc:
                logger.debug("Snusbase error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
