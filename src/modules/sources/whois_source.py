"""WHOIS source adapter for domain registration lookup."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class WhoisSource:
    """Query WHOIS data for domain registration information."""

    BASE_URL = "https://whois.arin.net/rest"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """WHOIS requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Look up WHOIS data for a domain or IP."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                # Try as IP first
                resp = await client.get(
                    f"{self.BASE_URL}/ip/{address}",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    leaks.append(RawLeak(
                        text=str(data),
                        source_name="whois",
                        source_url=f"https://whois.arin.net/rest/ip/{address}",
                    ))
                else:
                    # Try as ASN
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/asn/{address}",
                        headers={"Accept": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        leaks.append(RawLeak(
                            text=str(data),
                            source_name="whois",
                            source_url=f"https://whois.arin.net/rest/asn/{address}",
                        ))
            except Exception as exc:
                logger.debug("WHOIS error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
