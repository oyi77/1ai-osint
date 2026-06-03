"""Censys source adapter for certificate and host discovery."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class CensysSource:
    """Query Censys for certificates and hosts."""

    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("CENSYS_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Censys requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Censys for certificates and hosts."""
        if not self.api_key:
            logger.debug("Censys: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        # Censys uses API ID:SECRET format
        if ":" in self.api_key:
            api_id, api_secret = self.api_key.split(":", 1)
            auth = (api_id, api_secret)
        else:
            auth = (self.api_key, "")

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            # Search hosts
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/hosts/search",
                    params={"q": address, "per_page": 10},
                    auth=auth,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for hit in data.get("result", {}).get("hits", []):
                        leaks.append(
                            RawLeak(
                                text=str(hit)[:10000],
                                source_name="censys",
                                source_url=f"https://search.censys.io/hosts/{address}",
                            )
                        )
            except Exception as exc:
                logger.debug("Censys hosts error: %s", exc)

            # Search certificates
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/certificates/search",
                    params={"q": address, "per_page": 10},
                    auth=auth,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for hit in data.get("result", {}).get("hits", []):
                        leaks.append(
                            RawLeak(
                                text=str(hit)[:10000],
                                source_name="censys",
                                source_url="https://search.censys.io/certificates",
                            )
                        )
            except Exception as exc:
                logger.debug("Censys certificates error: %s", exc)

        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
