"""SecurityTrails source adapter for domain/IP reconnaissance."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class SecurityTrailsSource:
    """Query SecurityTrails for subdomains, DNS history, and IP info."""

    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: Optional[str] = None, request_delay: float = 2.0, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("SECURITYTRAILS_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """SecurityTrails requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Get subdomains and DNS data for a domain."""
        if not self.api_key:
            logger.debug("SecurityTrails: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"apikey": self.api_key}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # Get subdomains
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/domain/{address}/subdomains",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = data.get("subdomains", [])
                    if subdomains:
                        leaks.append(RawLeak(
                            text=f"Subdomains of {address}:\n" + "\n".join(f"{s}.{address}" for s in subdomains),
                            source_name="securitytrails",
                            source_url=f"https://securitytrails.com/domain/{address}",
                        ))
            except Exception as exc:
                logger.debug("SecurityTrails subdomains error: %s", exc)

            # Get DNS records
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/domain/{address}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    leaks.append(RawLeak(
                        text=str(data),
                        source_name="securitytrails",
                        source_url=f"https://securitytrails.com/domain/{address}",
                    ))
            except Exception as exc:
                logger.debug("SecurityTrails DNS error: %s", exc)

        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
