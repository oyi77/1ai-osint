"""Reddit source adapter with multiple fallback approaches."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_SUBREDDITS = [
    "cryptoleaks",
    "ethdev",
    "solana",
    "CryptoCurrency",
    "ethereum",
    "Bitcoin",
    "CryptoMarkets",
    "defi",
    "web3",
    "binance",
]

_KEYWORDS = [
    "seed phrase leak",
    "private key wallet",
    "mnemonic leaked",
    "crypto wallet dump",
]


class RedditSource:
    """Scan Reddit for leaked crypto keys with multiple fallback approaches."""

    # Alternative Reddit frontends (no auth required)
    ALTERNATIVE_FRONTENDS = [
        "https://redlib.catsarch.com",
        "https://redlib.tux.pizza",
        "https://safereddit.com",
        "https://libreddit.kavin.rocks",
    ]

    def __init__(
        self, max_per_sub: int = 50, request_delay: float = 1.0, timeout: float = 15.0
    ):
        self.max_per_sub = max_per_sub
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch Reddit posts using multiple fallback approaches."""
        leaks: list[RawLeak] = []
        seen_urls: set[str] = set()

        # Try each approach in order
        approaches = [
            ("reddit_json", self._fetch_via_reddit_json),
            ("pullpush", self._fetch_via_pullpush),
            ("alternative_frontend", self._fetch_via_alternative_frontend),
            ("reddit_search", self._fetch_via_reddit_search),
        ]

        for name, fetcher in approaches:
            try:
                result = await asyncio.wait_for(fetcher(seen_urls), timeout=30)
                leaks.extend(result)
                if leaks:
                    logger.info("Reddit: got %d leaks via %s", len(leaks), name)
                    break
            except asyncio.TimeoutError:
                logger.debug("Reddit %s timed out", name)
            except Exception as exc:
                logger.debug("Reddit %s error: %s", name, exc)

        return leaks

    async def _fetch_via_reddit_json(self, seen_urls: set[str]) -> list[RawLeak]:
        """Approach 1: Reddit's own JSON API."""
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "osint:crypto-leak-scanner:v1.0"}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for sub in _SUBREDDITS[:5]:  # Limit to avoid rate limits
                try:
                    await self._rate_limit()
                    url = f"https://www.reddit.com/r/{sub}/new.json?limit={self.max_per_sub}"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        for post in resp.json().get("data", {}).get("children", []):
                            data = post.get("data", {})
                            full_url = (
                                f"https://www.reddit.com{data.get('permalink', '')}"
                            )
                            if full_url not in seen_urls:
                                seen_urls.add(full_url)
                                combined = f"{data.get('title', '')}\n{data.get('selftext', '')}".strip()
                                if combined:
                                    leaks.append(
                                        RawLeak(
                                            text=combined,
                                            source_name="reddit",
                                            source_url=full_url,
                                        )
                                    )
                except Exception as exc:
                    logger.debug("Reddit JSON r/%s error: %s", sub, exc)
        return leaks

    async def _fetch_via_pullpush(self, seen_urls: set[str]) -> list[RawLeak]:
        """Approach 2: Pullpush.io API."""
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "osint:crypto-leak-scanner:v1.0"}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for sub in _SUBREDDITS[:3]:
                try:
                    await self._rate_limit()
                    url = f"https://api.pullpush.io/reddit/search/submission/?subreddit={sub}&size=25"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        for post in resp.json().get("data", []):
                            full_url = (
                                f"https://www.reddit.com{post.get('permalink', '')}"
                            )
                            if full_url not in seen_urls:
                                seen_urls.add(full_url)
                                combined = f"{post.get('title', '')}\n{post.get('selftext', '')}".strip()
                                if combined:
                                    leaks.append(
                                        RawLeak(
                                            text=combined,
                                            source_name="reddit",
                                            source_url=full_url,
                                        )
                                    )
                except Exception as exc:
                    logger.debug("pullpush r/%s error: %s", sub, exc)
        return leaks

    async def _fetch_via_alternative_frontend(
        self, seen_urls: set[str]
    ) -> list[RawLeak]:
        """Approach 3: Alternative Reddit frontends (redlib, libreddit, etc.)."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for frontend in self.ALTERNATIVE_FRONTENDS:
                try:
                    for sub in _SUBREDDITS[:3]:
                        await self._rate_limit()
                        url = f"{frontend}/r/{sub}/new"
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            # Parse the HTML for post content
                            text = resp.text
                            # Look for post titles and content
                            import re

                            # Simple extraction - look for post links and content
                            posts = re.findall(
                                r'<a[^>]*href="(/r/[^"]*)"[^>]*>([^<]*)</a>', text
                            )
                            for path, title in posts[:10]:
                                full_url = f"https://www.reddit.com{path}"
                                if full_url not in seen_urls and title.strip():
                                    seen_urls.add(full_url)
                                    leaks.append(
                                        RawLeak(
                                            text=title,
                                            source_name="reddit",
                                            source_url=full_url,
                                        )
                                    )
                            if leaks:
                                return leaks
                except Exception as exc:
                    logger.debug("Alternative frontend %s error: %s", frontend, exc)
        return leaks

    async def _fetch_via_reddit_search(self, seen_urls: set[str]) -> list[RawLeak]:
        """Approach 4: Reddit's search API."""
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "osint:crypto-leak-scanner:v1.0"}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for kw in _KEYWORDS:
                try:
                    await self._rate_limit()
                    url = f"https://www.reddit.com/search.json?q={kw.replace(' ', '+')}&limit=25&sort=new"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        for post in resp.json().get("data", {}).get("children", []):
                            data = post.get("data", {})
                            full_url = (
                                f"https://www.reddit.com{data.get('permalink', '')}"
                            )
                            if full_url not in seen_urls:
                                seen_urls.add(full_url)
                                combined = f"{data.get('title', '')}\n{data.get('selftext', '')}".strip()
                                if combined:
                                    leaks.append(
                                        RawLeak(
                                            text=combined,
                                            source_name="reddit",
                                            source_url=full_url,
                                        )
                                    )
                except Exception as exc:
                    logger.debug("Reddit search '%s' error: %s", kw, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Reddit for a specific address."""
        import re

        pattern = re.compile(re.escape(address), re.IGNORECASE)
        leaks = await self.fetch_raw_leaks()
        return [leak for leak in leaks if pattern.search(leak.text)]

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
