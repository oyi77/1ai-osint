"""ip-api.com source adapter — keyless IP geolocation / ownership.

Reverse-engineered / keyless public endpoint (no API key required):
``http://ip-api.com/json/<ip>``

The free tier is HTTP-only (HTTPS requires a paid key) and rate-limited to
~45 req/min; the adapter honors ``request_delay`` and never raises.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000
_DISPLAY_FIELDS = (
    "status",
    "country",
    "regionName",
    "city",
    "zip",
    "lat",
    "lon",
    "timezone",
    "isp",
    "org",
    "as",
    "reverse",
    "proxy",
    "hosting",
    "query",
)


class IpApiSource:
    """Keyless IP enrichment via ip-api.com."""

    BASE_URL = "http://ip-api.com/json"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: no global feed; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Geolocate / enrich ``address`` (an IPv4/IPv6 address)."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{self.BASE_URL}/{address}", params={"fields": ",".join(_DISPLAY_FIELDS)})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") != "success":
                        return []
                    for field in _DISPLAY_FIELDS:
                        value = data.get(field)
                        if value is None or value == "":
                            continue
                        leaks.append(
                            RawLeak(
                                text=f"{field}: {value}"[:_MAX_TEXT],
                                source_name="ip_api",
                                source_url=f"http://ip-api.com/{address}",
                            )
                        )
            except Exception as exc:
                logger.debug("ip_api error for %s: %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
