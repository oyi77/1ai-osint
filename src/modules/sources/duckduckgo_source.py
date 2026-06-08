"""DuckDuckGo dork scanner with multiple fallback approaches.

Scrapes DuckDuckGo HTML search results with Google dork queries.
Finds leaked .env files, wallet exports, and config dumps indexed by search engines.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_DORK_QUERIES = [
    '"PRIVATE_KEY=" filetype:env',
    '"seed phrase" "12 words" filetype:txt',
    '"mnemonic" "private" filetype:env',
    '"wallet.json" "private_key"',
    '"SECRET_KEY" "0x" filetype:env',
    '"PRIVATE_KEY" "0x" hex',
    '"seed" "mnemonic" "wallet" filetype:txt',
    '"bip39" "mnemonic" filetype:txt',
    '"private_key" "rpc_url" filetype:env',
    '"WALLET_PRIVATE_KEY"',
]


class DuckDuckGoSource:
    """Scan DuckDuckGo for indexed crypto leaks using dork queries."""

    # Multiple search endpoints for fallback
    SEARCH_ENDPOINTS = [
        ("duckduckgo_html", "https://html.duckduckgo.com/html/"),
        ("duckduckgo_lite", "https://lite.duckduckgo.com/lite/"),
        ("startpage", "https://www.startpage.com/sp/search"),
    ]

    def __init__(
        self, max_per_query: int = 10, request_delay: float = 2.0, timeout: float = 15.0
    ):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch leaks using multiple search engines as fallback."""
        import random as _random

        queries = _random.sample(_DORK_QUERIES, min(3, len(_DORK_QUERIES)))
        leaks: list[RawLeak] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        # Try each search endpoint
        for endpoint_name, search_url in self.SEARCH_ENDPOINTS:
            try:
                result = await asyncio.wait_for(
                    self._search_via_endpoint(search_url, queries, headers),
                    timeout=20,
                )
                leaks.extend(result)
                if leaks:
                    logger.info(
                        "DuckDuckGo: got %d leaks via %s", len(leaks), endpoint_name
                    )
                    break
            except asyncio.TimeoutError:
                logger.debug("DuckDuckGo %s timed out", endpoint_name)
            except Exception as exc:
                logger.debug("DuckDuckGo %s error: %s", endpoint_name, exc)

        return leaks

    async def _search_via_endpoint(
        self, search_url: str, queries: list[str], headers: dict
    ) -> list[RawLeak]:
        """Search via a specific endpoint."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for query in queries:
                try:
                    await self._rate_limit()
                    resp = await client.post(
                        search_url,
                        data={"q": query, "b": ""},
                        headers=headers,
                    )
                    if resp.status_code != 200:
                        continue

                    # Extract result URLs from HTML
                    urls = re.findall(r'href="(https?://[^"]+)"', resp.text)
                    # Filter out search engine internal links
                    urls = [
                        u
                        for u in urls
                        if not any(
                            x in u
                            for x in [
                                "duckduckgo.com",
                                "duck.co",
                                "startpage.com",
                                "google.com",
                            ]
                        )
                    ]
                    urls = list(dict.fromkeys(urls))[: self.max_per_query]

                    for url in urls:
                        try:
                            await self._rate_limit()
                            page = await client.get(url, headers=headers, timeout=10)
                            if page.status_code == 200 and len(page.text) > 50:
                                leaks.append(
                                    RawLeak(
                                        text=page.text,
                                        source_name="duckduckgo",
                                        source_url=url,
                                    )
                                )
                        except Exception:
                            pass
                except Exception as exc:
                    logger.debug("Search '%s' error: %s", query, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search DuckDuckGo for a specific address."""
        leaks: list[RawLeak] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for endpoint_name, search_url in self.SEARCH_ENDPOINTS:
                try:
                    await self._rate_limit()
                    resp = await client.post(
                        search_url,
                        data={"q": f'"{address}"', "b": ""},
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        urls = re.findall(r'href="(https?://[^"]+)"', resp.text)
                        urls = [
                            u
                            for u in urls
                            if not any(
                                x in u
                                for x in ["duckduckgo.com", "duck.co", "startpage.com"]
                            )
                        ]
                        urls = list(dict.fromkeys(urls))[:5]

                        for url in urls:
                            try:
                                await self._rate_limit()
                                page = await client.get(
                                    url, headers=headers, timeout=10
                                )
                                if (
                                    page.status_code == 200
                                    and address.lower() in page.text.lower()
                                ):
                                    leaks.append(
                                        RawLeak(
                                            text=page.text,
                                            source_name="duckduckgo",
                                            source_url=url,
                                        )
                                    )
                            except Exception:
                                pass
                        if leaks:
                            break
                except Exception as exc:
                    logger.debug("DuckDuckGo search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
