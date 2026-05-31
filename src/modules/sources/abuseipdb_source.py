"""AbuseIPDB source adapter for IP reputation lookup."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class AbuseIPDBSource:
    """Query AbuseIPDB for IP reputation and abuse reports."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None, request_delay: float = 2.0, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """AbuseIPDB requires an IP target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search AbuseIPDB for IP reputation."""
        if not self.api_key:
            logger.debug("AbuseIPDB: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        headers = {"Key": self.api_key, "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/check",
                    params={"ipAddress": address, "maxAgeInDays": 90},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    leaks.append(RawLeak(
                        text=f"IP: {address}\n"
                             f"Abuse confidence: {data.get('abuseConfidenceScore', 'unknown')}%\n"
                             f"ISP: {data.get('isp', 'unknown')}\n"
                             f"Country: {data.get('countryCode', 'unknown')}\n"
                             f"Reports: {data.get('totalReports', 0)}",
                        source_name="abuseipdb",
                        source_url=f"https://www.abuseipdb.com/check/{address}",
                    ))
            except Exception as exc:
                logger.debug("AbuseIPDB error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
