"""RubyGems source adapter for finding leaked keys in Ruby gems."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "private key",
    "mnemonic",
    "wallet",
    "api key",
    "secret",
    "credentials",
]


class RubygemsSource:
    """Scan RubyGems for gems with leaked crypto keys."""

    BASE_URL = "https://rubygems.org/api/v1"

    def __init__(
        self, max_per_query: int = 20, request_delay: float = 1.0, timeout: float = 15.0
    ):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search RubyGems for gems with crypto key leaks."""
        leaks: list[RawLeak] = []
        seen_gems: set[str] = set()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for query in _QUERIES[:4]:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/search.json",
                        params={"query": query},
                    )
                    if resp.status_code == 200:
                        for gem in resp.json()[: self.max_per_query]:
                            gem_name = gem.get("name", "")
                            if gem_name in seen_gems:
                                continue
                            seen_gems.add(gem_name)
                            desc = gem.get("info", "")
                            if desc:
                                leaks.append(
                                    RawLeak(
                                        text=desc,
                                        source_name="rubygems",
                                        source_url=f"https://rubygems.org/gems/{gem_name}",
                                    )
                                )
                except Exception as exc:
                    logger.debug("RubyGems search '%s' error: %s", query, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search RubyGems for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/search.json",
                    params={"query": address},
                )
                if resp.status_code == 200:
                    for gem in resp.json()[:5]:
                        desc = gem.get("info", "")
                        if desc:
                            leaks.append(
                                RawLeak(
                                    text=desc,
                                    source_name="rubygems",
                                    source_url=f"https://rubygems.org/gems/{gem.get('name', '')}",
                                )
                            )
            except Exception as exc:
                logger.debug("RubyGems address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
