"""LeakCheck source adapter for credential leak lookup."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class LeakcheckSource:
    """Query LeakCheck for leaked credentials."""

    BASE_URL = "https://leakcheck.io/api/public"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("LEAKCHECK_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """LeakCheck requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search LeakCheck for leaked credentials."""
        if not self.api_key:
            logger.debug("LeakCheck: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.BASE_URL,
                    params={"check": address},
                    headers={"X-API-Key": self.api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("found", 0) > 0:
                        for entry in data.get("sources", []):
                            structured: dict[str, str] = {}
                            if isinstance(entry, dict):
                                for field in (
                                    "name",
                                    "date",
                                    "email",
                                    "username",
                                    "password",
                                    "phone",
                                ):
                                    val = entry.get(field, "")
                                    if val:
                                        key = (
                                            "breach_name" if field == "name" else field
                                        )
                                        structured[key] = str(val)
                            leaks.append(
                                RawLeak(
                                    text=f"Leak found for {address}: {entry}",
                                    source_name="leakcheck",
                                    source_url=f"https://leakcheck.io/check/{address}",
                                    metadata=structured,
                                )
                            )
            except Exception as exc:
                logger.debug("LeakCheck error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
