"""Cert Spotter keyless source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/v1/issuances`` — Certificate Transparency issuance history for a domain,
  expanded to the full ``dns_names`` set per certificate.

Deduplicates names, honors ``request_delay`` between calls, never raises.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000


class CertSpotterSource:
    """Keyless subdomain enumeration via Cert Spotter's public CT API."""

    BASE_URL = "https://api.certspotter.com/v1"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enumerate subdomains from certificate transparency issuances."""
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/issuances?domain={address}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/issuances",
                    params={
                        "domain": address,
                        "include_subdomains": "true",
                        "expand": "dns_names",
                    },
                )
                if resp.status_code == 200:
                    seen: set[str] = set()
                    for issuance in resp.json() or []:
                        for name in issuance.get("dns_names") or []:
                            name = str(name).lower().rstrip(".")
                            if name and name not in seen:
                                seen.add(name)
                                leaks.append(
                                    RawLeak(
                                        text=name[:_MAX_TEXT],
                                        source_name="certspotter",
                                        source_url=source_url,
                                    )
                                )
            except Exception as exc:
                logger.debug("certspotter error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
