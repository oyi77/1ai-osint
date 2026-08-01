"""Shodan source adapter for exposed service discovery."""

from __future__ import annotations

import asyncio
import logging
import os
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class ShodanSource:
    """Query Shodan for exposed services and devices."""

    BASE_URL = "https://api.shodan.io"

    def __init__(
        self,
        api_key: str | None = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Shodan requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Shodan for exposed services on an IP or domain.

        Without an API key this falls back to the keyless Shodan InternetDB
        endpoint (IPv4 only) so scans stay useful in 0-API mode.
        """
        if not self.api_key:
            logger.debug("Shodan: no API key configured, using keyless InternetDB fallback")
            return await self._internetdb_fallback(address)

        leaks: list[RawLeak] = []
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/shodan/host/{address}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Extract banner data from each service
                    for service in data.get("data", []):
                        banner = service.get("data", "")
                        if banner:
                            leaks.append(
                                RawLeak(
                                    text=banner[:10000],
                                    source_name="shodan",
                                    source_url=f"https://www.shodan.io/host/{address}",
                                )
                            )
            except Exception as exc:
                logger.debug("Shodan error for '%s': %s", address, exc)
        return leaks

    async def _internetdb_fallback(self, address: str) -> list[RawLeak]:
        """Keyless fallback: Shodan InternetDB (no API key, IPv4 only).

        Returns empty list for domains, non-IPv4 inputs, or any error —
        this adapter must never raise or crash a scan.
        """
        import ipaddress

        try:
            ip = str(ipaddress.IPv4Address(address.strip()))
        except (ValueError, AttributeError):
            return []

        leaks: list[RawLeak] = []
        url = f"https://internetdb.shodan.io/{ip}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(url)
                if resp.status_code != 200:
                    return []
                data = resp.json()
            except Exception as exc:
                logger.debug("Shodan InternetDB error for '%s': %s", address, exc)
                return []

        for port in data.get("ports", []):
            leaks.append(RawLeak(text=f"Open port: {port}", source_name="shodan_internetdb", source_url=url))
        for hostname in data.get("hostnames", []):
            leaks.append(RawLeak(text=f"Hostname: {hostname}", source_name="shodan_internetdb", source_url=url))
        for cpe in data.get("cpes", []):
            leaks.append(RawLeak(text=f"CPE: {cpe}", source_name="shodan_internetdb", source_url=url))
        for vuln in data.get("vulns", []):
            leaks.append(RawLeak(text=f"Vulnerability: {vuln}", source_name="shodan_internetdb", source_url=url))
        for tag in data.get("tags", []):
            leaks.append(RawLeak(text=f"Tag: {tag}", source_name="shodan_internetdb", source_url=url))
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
