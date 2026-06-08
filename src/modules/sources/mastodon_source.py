"""Mastodon source adapter for fediverse OSINT."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class MastodonSource:
    """Search Mastodon instances for crypto-related posts."""

    INSTANCES = [
        "https://mastodon.social",
        "https://fosstodon.org",
        "https://infosec.exchange",
    ]

    def __init__(self, request_delay: float = 2.0, timeout: float = 15.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search Mastodon for crypto-related posts."""
        leaks: list[RawLeak] = []
        queries = ["private key", "mnemonic", "seed phrase", "wallet dump"]

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for instance in self.INSTANCES:
                for query in queries[:2]:
                    try:
                        await self._rate_limit()
                        resp = await client.get(
                            f"{instance}/api/v2/search",
                            params={"q": query, "type": "statuses", "limit": 10},
                        )
                        if resp.status_code == 200:
                            for status in resp.json().get("statuses", []):
                                content = status.get("content", "")
                                url = status.get("url", "")
                                if content:
                                    leaks.append(
                                        RawLeak(
                                            text=content[:5000],
                                            source_name="mastodon",
                                            source_url=url,
                                        )
                                    )
                    except Exception as exc:
                        logger.debug("Mastodon %s search error: %s", instance, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Mastodon for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for instance in self.INSTANCES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{instance}/api/v2/search",
                        params={"q": address, "type": "statuses", "limit": 5},
                    )
                    if resp.status_code == 200:
                        for status in resp.json().get("statuses", []):
                            content = status.get("content", "")
                            url = status.get("url", "")
                            if content and address.lower() in content.lower():
                                leaks.append(
                                    RawLeak(
                                        text=content[:5000],
                                        source_name="mastodon",
                                        source_url=url,
                                    )
                                )
                except Exception as exc:
                    logger.debug("Mastodon %s address search error: %s", instance, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
