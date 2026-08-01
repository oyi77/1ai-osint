"""Anubis keyless source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/anubis/subdomains/{domain}`` — JSON array of known subdomains from the
  Anubis (jldc.me) subdomain index.

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


class AnubisSource:
    """Keyless subdomain enumeration via the Anubis (jldc.me) index."""

    BASE_URL = "https://jldc.me/anubis/subdomains"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enumerate subdomains from the Anubis JSON index."""
        leaks: list[RawLeak] = []
        domain = address.strip().lower().rstrip(".")
        if not domain:
            return []
        source_url = f"{self.BASE_URL}/{domain}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code == 200:
                    seen: set[str] = set()
                    for name in resp.json() or []:
                        name = str(name).lower().rstrip(".")
                        if name and name not in seen:
                            seen.add(name)
                            leaks.append(
                                RawLeak(
                                    text=name[:_MAX_TEXT],
                                    source_name="anubis",
                                    source_url=source_url,
                                )
                            )
            except Exception as exc:
                logger.debug("anubis error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
