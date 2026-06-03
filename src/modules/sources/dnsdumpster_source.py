"""DNSDumpster source adapter for DNS reconnaissance."""

from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class DNSDumpsterSource:
    """Query DNSDumpster for DNS records and subdomains."""

    BASE_URL = "https://dnsdumpster.com"

    def __init__(self, request_delay: float = 3.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """DNSDumpster requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Get DNS records for a domain."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                # Get CSRF token
                resp = await client.get(self.BASE_URL)
                if resp.status_code != 200:
                    return leaks
                # Extract CSRF token from cookies
                csrf = None
                for cookie in client.cookies.jar:
                    if cookie.name == "csrftoken":
                        csrf = cookie.value
                        break
                if not csrf:
                    return leaks
                await self._rate_limit()
                resp = await client.post(
                    self.BASE_URL,
                    data={
                        "csrfmiddlewaretoken": csrf,
                        "targetip": address,
                    },
                    headers={
                        "Referer": self.BASE_URL,
                        "X-CSRFToken": csrf,
                    },
                )
                if resp.status_code == 200:
                    text = resp.text
                    if address.lower() in text.lower():
                        leaks.append(
                            RawLeak(
                                text=text[:50000],
                                source_name="dnsdumpster",
                                source_url=f"{self.BASE_URL}/?host={address}",
                            )
                        )
            except Exception as exc:
                logger.debug("DNSDumpster error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
