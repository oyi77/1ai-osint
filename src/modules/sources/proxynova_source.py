"""ProxyNova keyless breach-source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/combine?query={q}`` — historical breach / paste lines matching an
  email, username, phone, or IP via the public ProxyNova combine search.

Honors ``request_delay`` between calls and never raises.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000


class ProxynovaSource:
    """Keyless query -> historical breach lines via ProxyNova combine."""

    BASE_URL = "https://api.proxynova.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search combine for breach/paste lines matching the query string.

        The combine endpoint accepts email, username, phone, or IP queries.
        Empty or whitespace-only input is rejected before any HTTP call.
        """
        query = address.strip()
        if not query:
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/combine?query={query}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code == 200:
                    data = resp.json().get("data") or {}
                    seen: set[tuple[str, str]] = set()
                    for domain, entries in data.items():
                        for entry in entries or []:
                            line = (entry or {}).get("line")
                            if not line:
                                continue
                            pair = (domain, line)
                            if pair in seen:
                                continue
                            seen.add(pair)
                            leaks.append(
                                RawLeak(
                                    text=f"{domain} | {line}"[:_MAX_TEXT],
                                    source_name="proxynova",
                                    source_url=source_url,
                                )
                            )
            except Exception as exc:
                logger.debug("proxynova error for %s: %s", query, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
