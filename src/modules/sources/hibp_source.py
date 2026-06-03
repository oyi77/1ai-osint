"""Have I Been Pwned source adapter for breach lookup."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class HIBPSource:
    """Query Have I Been Pwned for breach data."""

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("HIBP_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """HIBP requires an email target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search HIBP for breaches associated with an email."""
        if not self.api_key:
            logger.debug("HIBP: no API key configured, skipping")
            return []

        if "@" not in address:
            return []

        leaks: list[RawLeak] = []
        headers = {"hibp-api-key": self.api_key}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/breachedaccount/{address}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    breaches = resp.json()
                    for breach in breaches:
                        data_classes = breach.get("DataClasses", [])
                        structured: dict[str, object] = {
                            "breach_name": str(breach.get("Name", "")),
                            "breach_date": str(breach.get("BreachDate", "")),
                            "data_classes": data_classes
                            if isinstance(data_classes, list)
                            else [],
                        }
                        for k in ("Description", "Domain"):
                            if breach.get(k):
                                structured[k.lower()] = str(breach[k])
                        leaks.append(
                            RawLeak(
                                text=f"Breach: {breach.get('Name', '')} on {breach.get('BreachDate', '')}\n"
                                f"Data classes: {', '.join(data_classes)}",
                                source_name="hibp",
                                source_url=f"https://haveibeenpwned.com/account/{address}",
                                metadata=dict(structured),
                            )
                        )
                elif resp.status_code == 404:
                    # No breaches found
                    pass
            except Exception as exc:
                logger.debug("HIBP error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
