"""BGPView keyless source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/ip/{ip}`` — ASN, announced prefixes, RIR allocation, and location for an
  IPv4/IPv6 address via the public BGPView API.

Honors ``request_delay`` between calls and never raises.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000


class BgpViewSource:
    """Keyless IP -> ASN / prefix / RIR / geo enrichment via BGPView."""

    BASE_URL = "https://api.bgpview.io"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich an IPv4/IPv6 address with ASN/prefix/RIR/location leaks."""
        address = address.strip()
        if not self._looks_like_ip(address):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/ip/{address}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code == 200:
                    data = resp.json().get("data") or {}
                    asn = data.get("asn") or {}
                    asn_num = asn.get("asn")
                    if asn_num is not None:
                        leaks.append(
                            RawLeak(
                                text=f"asn: {asn_num}"[:_MAX_TEXT],
                                source_name="bgpview",
                                source_url=source_url,
                            )
                        )
                    name = asn.get("name")
                    desc = asn.get("description")
                    if name or desc:
                        label = " / ".join(x for x in (name, desc) if x)
                        leaks.append(
                            RawLeak(
                                text=f"asn name: {label}"[:_MAX_TEXT],
                                source_name="bgpview",
                                source_url=source_url,
                            )
                        )
                    for prefix in data.get("prefixes") or []:
                        p = prefix.get("prefix")
                        if p:
                            leaks.append(
                                RawLeak(
                                    text=f"prefix: {p}"[:_MAX_TEXT],
                                    source_name="bgpview",
                                    source_url=source_url,
                                )
                            )
                    rir = (data.get("rir_allocation") or {}).get("rir_name")
                    if rir:
                        leaks.append(
                            RawLeak(
                                text=f"rir: {rir}"[:_MAX_TEXT],
                                source_name="bgpview",
                                source_url=source_url,
                            )
                        )
                    country = (data.get("location") or {}).get("country")
                    if country:
                        leaks.append(
                            RawLeak(
                                text=f"country: {country}"[:_MAX_TEXT],
                                source_name="bgpview",
                                source_url=source_url,
                            )
                        )
            except Exception as exc:
                logger.debug("bgpview error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
