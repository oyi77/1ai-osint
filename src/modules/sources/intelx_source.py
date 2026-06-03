"""Intelligence X source adapter for OSINT search."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class IntelxSource:
    """Query Intelligence X for leaked data and intelligence."""

    BASE_URL = "https://2.intelx.io"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("INTELX_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Intelligence X requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Intelligence X for leaked data."""
        if not self.api_key:
            logger.debug("Intelligence X: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"x-key": self.api_key}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    f"{self.BASE_URL}/phonebook/search",
                    json={"term": address, "maxresults": 100, "media": 0, "target": 0},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    search_id = data.get("id", "")
                    if search_id:
                        # Get results
                        await self._rate_limit()
                        result_resp = await client.get(
                            f"{self.BASE_URL}/phonebook/search/result",
                            params={"id": search_id, "limit": 100},
                            headers=headers,
                        )
                        if result_resp.status_code == 200:
                            results = result_resp.json()
                            for record in results.get("records", []):
                                structured: dict[str, str] = {}
                                if isinstance(record, dict):
                                    for field in (
                                        "name",
                                        "email",
                                        "username",
                                        "phone",
                                        "domain",
                                        "password",
                                        "ip",
                                    ):
                                        val = record.get(field, "")
                                        if val:
                                            structured[field] = str(val)
                                leaks.append(
                                    RawLeak(
                                        text=str(record),
                                        source_name="intelx",
                                        source_url=f"https://intelx.io/?s={address}",
                                        metadata=structured,
                                    )
                                )
            except Exception as exc:
                logger.debug("Intelligence X error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
