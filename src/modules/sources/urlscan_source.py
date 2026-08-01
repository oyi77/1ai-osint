"""urlscan.io keyless source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/api/v1/search/?q=domain:{domain}&size=100`` — recent scan results for a
  domain; each result yields a ``url`` leak plus an ``ip``/ASN leak when the
  page payload carries them.

Deduplicates URLs and IPs, honors ``request_delay`` between calls, never raises.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000


class UrlScanSource:
    """Keyless URL/scan index lookup via the urlscan.io public API."""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enumerate scanned URLs and host IPs for a domain."""
        leaks: list[RawLeak] = []
        domain = address.strip().lower().rstrip(".")
        if not domain:
            return []
        source_url = f"{self.BASE_URL}/search/?q=domain:{domain}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/search/",
                    params={"q": f"domain:{domain}", "size": 100},
                )
                if resp.status_code == 200:
                    seen_urls: set[str] = set()
                    seen_ips: set[str] = set()
                    for result in resp.json().get("results") or []:
                        page = result.get("page") or {}
                        url = page.get("url")
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            leaks.append(
                                RawLeak(
                                    text=f"url: {url}"[:_MAX_TEXT],
                                    source_name="urlscan",
                                    source_url=source_url,
                                )
                            )
                        ip = page.get("ip")
                        if ip:
                            asn = page.get("asn")
                            key = f"{ip}|{asn or ''}"
                            if key not in seen_ips:
                                seen_ips.add(key)
                                label = f"ip: {ip}" + (f" ({asn})" if asn else "")
                                leaks.append(
                                    RawLeak(
                                        text=label[:_MAX_TEXT],
                                        source_name="urlscan",
                                        source_url=source_url,
                                    )
                                )
            except Exception as exc:
                logger.debug("urlscan error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
