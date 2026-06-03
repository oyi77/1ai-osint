"""crt.sh certificate transparency source adapter."""

from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class CrtShSource:
    """Scan crt.sh certificate transparency logs for domain enumeration."""

    BASE_URL = "https://crt.sh"

    def __init__(
        self, max_results: int = 100, request_delay: float = 2.0, timeout: float = 30.0
    ):
        self.max_results = max_results
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch recent certificate transparency entries."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/?output=json",
                    params={"limit": self.max_results},
                )
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        if name_value:
                            leaks.append(
                                RawLeak(
                                    text=name_value,
                                    source_name="crtsh",
                                    source_url=f"https://crt.sh/?id={entry.get('id', '')}",
                                )
                            )
            except Exception as exc:
                logger.debug("crt.sh error: %s", exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search crt.sh for a specific domain."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/?output=json&q={address}",
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        name_value = entry.get("name_value", "")
                        if name_value:
                            leaks.append(
                                RawLeak(
                                    text=name_value,
                                    source_name="crtsh",
                                    source_url=f"https://crt.sh/?id={entry.get('id', '')}",
                                )
                            )
            except Exception as exc:
                logger.debug("crt.sh search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
