"""DuckDuckGo dork scanner for crypto leak discovery.

Scrapes DuckDuckGo HTML search results with Google dork queries.
Finds leaked .env files, wallet exports, and config dumps indexed by search engines.
"""
from __future__ import annotations
import asyncio
import logging
import re
import time
import httpx
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

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

    SEARCH_URL = "https://html.duckduckgo.com/html/"

    def __init__(self, max_per_query: int = 10, request_delay: float = 3.0, timeout: float = 30.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        import random as _random
        queries = _random.sample(_DORK_QUERIES, min(4, len(_DORK_QUERIES)))
        leaks: list[RawLeak] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for query in queries:
                try:
                    await self._rate_limit()
                    resp = await client.post(
                        self.SEARCH_URL,
                        data={"q": query, "b": ""},
                        headers=headers,
                    )
                    if resp.status_code != 200:
                        logger.debug("DuckDuckGo returned %d for '%s'", resp.status_code, query)
                        continue
                    # Extract result URLs from HTML
                    urls = re.findall(r'href="(https?://[^"]+)"', resp.text)
                    # Filter out DuckDuckGo internal links
                    urls = [u for u in urls if "duckduckgo.com" not in u and "duck.co" not in u]
                    urls = list(dict.fromkeys(urls))[:self.max_per_query]

                    for url in urls:
                        try:
                            await self._rate_limit()
                            page = await client.get(url, headers=headers, timeout=10)
                            if page.status_code == 200 and len(page.text) > 50:
                                leaks.append(RawLeak(text=page.text, source_name="duckduckgo", source_url=url))
                        except Exception:
                            pass
                except Exception as exc:
                    logger.error("DuckDuckGo search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
