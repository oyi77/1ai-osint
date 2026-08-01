"""DNS records source adapter — keyless Google DoH resolver.

Reverse-engineered / keyless public endpoint (no API key required):
``https://dns.google/resolve?name=<domain>&type=<TYPE>``

Enumerates the common record classes for a domain so deep scans surface
infrastructure (A/AAAA/NS/MX/TXT/CNAME) without any vendor credential.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000
_RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME")
_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    257: "CAA",
}


class DnsRecordsSource:
    """Keyless DNS record enumeration via the Google DoH resolver."""

    BASE_URL = "https://dns.google/resolve"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: no global feed; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Resolve the common record classes for ``address`` (a domain)."""
        leaks: list[RawLeak] = []
        seen: set[str] = set()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for rtype in _RECORD_TYPES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        self.BASE_URL,
                        params={"name": address, "type": rtype},
                    )
                    if resp.status_code != 200:
                        continue
                    for answer in resp.json().get("Answer") or []:
                        rdata = str(answer.get("data", "")).strip()
                        if not rdata:
                            continue
                        label = _TYPE_NAMES.get(int(answer.get("type", 0)), rtype)
                        key = f"{label}|{rdata}"
                        if key in seen:
                            continue
                        seen.add(key)
                        ttl = answer.get("TTL")
                        text = f"{label} {rdata}" if ttl is None else f"{label} {rdata} (TTL {ttl})"
                        leaks.append(
                            RawLeak(
                                text=text[:_MAX_TEXT],
                                source_name="dns_records",
                                source_url=(f"https://dns.google/resolve?name={address}&type={rtype}"),
                            )
                        )
                except Exception as exc:
                    logger.debug("dns_records error for %s (%s): %s", address, rtype, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
