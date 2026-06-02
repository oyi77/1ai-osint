"""Scylla source adapter for breach data lookup."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class ScyllaSource:
    """Query Scylla.sh for breach data and leaked credentials."""

    BASE_URL = "https://scylla.sh/api/search"

    def __init__(self, api_key: Optional[str] = None, request_delay: float = 2.0, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("SCYLLA_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Scylla requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Scylla for breached credentials."""
        if not self.api_key:
            logger.debug("Scylla: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.BASE_URL,
                    params={"query": address, "size": 100},
                    headers=headers,
                )
                if resp.status_code == 200:
                    results = resp.json()
                    if isinstance(results, list):
                        for entry in results:
                            structured: dict[str, str] = {}
                            if isinstance(entry, dict):
                                for field in ("email", "username", "phone", "domain", "password",
                                              "password_hash", "name", "ip_address"):
                                    val = entry.get(field, "")
                                    if val:
                                        structured[field] = str(val)
                            leaks.append(RawLeak(
                                text=str(entry)[:5000],
                                source_name="scylla",
                                source_url=f"https://scylla.sh/search?q={address}",
                                metadata=structured,
                            ))
            except Exception as exc:
                logger.debug("Scylla error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
