"""HackerTarget keyless source adapter.

Reverse-engineered / keyless public endpoints (no API key required):

- ``hostsearch`` — subdomains for a domain, CSV lines ``host,ip``.
- ``reverseiplookup`` — hostnames on an IP, one per line.

Free tier is rate-limited by the provider; the adapter honors
``request_delay`` between calls and never raises.
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


class HackerTargetSource:
    """Keyless subdomain / reverse-IP enumeration via HackerTarget."""

    BASE_URL = "https://api.hackertarget.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enumerate subdomains (domain) or reverse-IP hosts (IPv4/IPv6)."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                is_ip = self._looks_like_ip(address)
                if is_ip:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/reverseiplookup/",
                        params={"q": address},
                    )
                    if resp.status_code == 200:
                        for line in resp.text.splitlines():
                            host = line.strip()
                            if host and not host.lower().startswith(("error", "api count exceeded")):
                                leaks.append(
                                    RawLeak(
                                        text=host[:_MAX_TEXT],
                                        source_name="hackertarget",
                                        source_url=(f"https://api.hackertarget.com/reverseiplookup/?q={address}"),
                                    )
                                )
                else:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/hostsearch/",
                        params={"q": address},
                    )
                    if resp.status_code == 200:
                        for line in resp.text.splitlines():
                            parts = line.split(",")
                            if len(parts) >= 2:
                                host, ip = parts[0].strip(), parts[1].strip()
                                if host and not host.lower().startswith("error"):
                                    leaks.append(
                                        RawLeak(
                                            text=f"{host} -> {ip}"[:_MAX_TEXT],
                                            source_name="hackertarget",
                                            source_url=(f"https://api.hackertarget.com/hostsearch/?q={address}"),
                                        )
                                    )
            except Exception as exc:
                logger.debug("hackertarget error for %s: %s", address, exc)
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
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False
