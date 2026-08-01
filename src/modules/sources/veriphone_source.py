"""Veriphone keyless phone-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/v2/verify?phone={phone}`` — carrier, line type, country, and
  international/national formatting for a phone number via the public
  Veriphone API.

Honors ``request_delay`` between calls and never raises.
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

_DIGITS_RE = re.compile(r"[^0-9]")


class VeriPhoneSource:
    """Keyless phone -> carrier / line type / country enrichment via Veriphone."""

    BASE_URL = "https://api.veriphone.io"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a phone number with carrier / line type / country leaks."""
        phone = address.strip()
        if not self._looks_like_phone(phone):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/v2/verify?phone={phone}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success" and data.get("phone_valid"):
                        for label, value in (
                            ("carrier", data.get("carrier")),
                            ("line type", data.get("line_type")),
                            ("country", data.get("country")),
                            ("international", data.get("international_format")),
                            ("national", data.get("national_format")),
                        ):
                            if not value:
                                continue
                            text = f"{label}: {value}"
                            if label == "country":
                                prefix = data.get("country_prefix")
                                if prefix:
                                    text = f"country: {value} ({prefix})"
                            leaks.append(
                                RawLeak(
                                    text=text[:_MAX_TEXT],
                                    source_name="veriphone",
                                    source_url=source_url,
                                )
                            )
            except Exception as exc:
                logger.debug("veriphone error for %s: %s", phone, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()

    @staticmethod
    def _looks_like_phone(value: str) -> bool:
        digits = _DIGITS_RE.sub("", value)
        return 7 <= len(digits) <= 15
