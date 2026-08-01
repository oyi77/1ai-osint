"""RapidDNS keyless source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/subdomain/{domain}?full=1`` — HTML subdomain search; table cells ending
  with the query domain become subdomain leaks.

Parses the HTML table cells (regex), strips nested tags, deduplicates, honors
``request_delay`` between calls, and never raises.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000


class RapidDnsSource:
    """Keyless subdomain enumeration via RapidDNS public search."""

    BASE_URL = "https://rapiddns.io"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enumerate subdomains from the RapidDNS HTML search result table."""
        leaks: list[RawLeak] = []
        domain = address.strip().lower().rstrip(".")
        if not domain:
            return []
        source_url = f"{self.BASE_URL}/subdomain/{domain}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{source_url}?full=1")
                if resp.status_code == 200:
                    seen: set[str] = set()
                    cells = re.findall(r"<td[^>]*>(.*?)</td>", resp.text, flags=re.S | re.I)
                    suffix = "." + domain
                    for cell in cells:
                        text = re.sub(r"<[^>]+>", "", cell).strip().lower()
                        if text == domain or text.endswith(suffix):
                            if text not in seen:
                                seen.add(text)
                                leaks.append(
                                    RawLeak(
                                        text=text[:_MAX_TEXT],
                                        source_name="rapiddns",
                                        source_url=source_url,
                                    )
                                )
            except Exception as exc:
                logger.debug("rapiddns error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
