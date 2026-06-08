"""Hunter.io source adapter for email enumeration."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class HunterSource:
    """Query Hunter.io for email addresses associated with a domain."""

    BASE_URL = "https://api.hunter.io/v2"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("HUNTER_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Hunter.io requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Find email addresses associated with a domain."""
        if not self.api_key:
            logger.debug("Hunter.io: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/domain-search",
                    params={
                        "domain": address,
                        "api_key": self.api_key,
                        "limit": 100,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    emails = data.get("emails", [])
                    if emails:
                        email_list = [
                            e.get("value", "") for e in emails if e.get("value")
                        ]
                        leaks.append(
                            RawLeak(
                                text=f"Emails found for {address}:\n"
                                + "\n".join(email_list),
                                source_name="hunter",
                                source_url=f"https://hunter.io/search/{address}",
                            )
                        )
            except Exception as exc:
                logger.debug("Hunter.io error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
