"""Discord source adapter for OSINT on Discord servers."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class DiscordSource:
    """Search Discord for crypto-related content via web scraping."""

    def __init__(self, request_delay: float = 2.0, timeout: float = 15.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search for Discord crypto leaks via web search."""
        leaks: list[RawLeak] = []
        queries = [
            "site:discord.com private key leak",
            "site:discord.com mnemonic seed phrase",
            "site:discord.com wallet dump",
        ]
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for query in queries:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        "https://html.duckduckgo.com/html/",
                        data={"q": query},
                    )
                    if resp.status_code == 200:
                        import re

                        urls = re.findall(
                            r'href="(https?://discord\.com[^"]+)"', resp.text
                        )
                        for url in urls[:5]:
                            leaks.append(
                                RawLeak(
                                    text=f"Discord link found: {url}",
                                    source_name="discord",
                                    source_url=url,
                                )
                            )
                except Exception as exc:
                    logger.debug("Discord search error: %s", exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Discord for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    "https://html.duckduckgo.com/html/",
                    data={"q": f'site:discord.com "{address}"'},
                )
                if resp.status_code == 200:
                    import re

                    urls = re.findall(r'href="(https?://discord\.com[^"]+)"', resp.text)
                    for url in urls[:5]:
                        leaks.append(
                            RawLeak(
                                text=f"Discord mention: {address}",
                                source_name="discord",
                                source_url=url,
                            )
                        )
            except Exception as exc:
                logger.debug("Discord address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
