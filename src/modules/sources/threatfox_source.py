"""ThreatFox source adapter for IOC intelligence."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class ThreatFoxSource:
    """Query ThreatFox for indicators of compromise."""

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1"

    def __init__(self, request_delay: float = 2.0, timeout: float = 15.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch recent IOCs from ThreatFox."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    self.BASE_URL,
                    json={"query": "get_iocs", "days": 1},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for ioc in data.get("data", []):
                        ioc_value = ioc.get("ioc", "")
                        ioc_type = ioc.get("ioc_type", "")
                        malware = ioc.get("malware", "")
                        if ioc_value:
                            leaks.append(RawLeak(
                                text=f"IOC: {ioc_value}\nType: {ioc_type}\nMalware: {malware}",
                                source_name="threatfox",
                                source_url=f"https://threatfox.ch/browse/ioc/{ioc_value}/",
                            ))
            except Exception as exc:
                logger.debug("ThreatFox error: %s", exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search ThreatFox for a specific IOC."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.post(
                    self.BASE_URL,
                    json={"query": "search_ioc", "search_term": address},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for ioc in data.get("data", []):
                        leaks.append(RawLeak(
                            text=str(ioc)[:5000],
                            source_name="threatfox",
                            source_url=f"https://threatfox.ch/browse/ioc/{address}/",
                        ))
            except Exception as exc:
                logger.debug("ThreatFox search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
