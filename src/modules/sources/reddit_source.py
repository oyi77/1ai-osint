"""Reddit source adapter for crypto leak discovery."""
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

class RedditSource:
    """Scan Reddit for leaked crypto keys/mnemonics using the free JSON API."""

    def __init__(self, max_per_sub: int = 100, request_delay: float = 2.0, timeout: float = 30.0):
        self.max_per_sub = max_per_sub
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch Reddit posts via pullpush.io — both by subreddit and by keyword search."""
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "osint:crypto-leak-scanner:v1.0"}
        seen_urls: set[str] = set()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # 1. Scan specific subreddits
            for sub in _SUBREDDITS:
                try:
                    await self._rate_limit()
                    url = f"https://api.pullpush.io/reddit/search/submission/?subreddit={sub}&size={self.max_per_sub}"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 200:
                        logger.debug("pullpush r/%s returned %d", sub, resp.status_code)
                        continue
                    for post in resp.json().get("data", []):
                        full_url = f"https://www.reddit.com{post.get('permalink', '')}"
                        if full_url in seen_urls:
                            continue
                        seen_urls.add(full_url)
                        combined = f"{post.get('title', '')}\n{post.get('selftext', '')}".strip()
                        if combined:
                            leaks.append(RawLeak(text=combined, source_name="reddit", source_url=full_url))
                except Exception as exc:
                    logger.error("Reddit r/%s error: %s", sub, exc)

            # 2. Keyword search across all Reddit
            _KEYWORDS = ["seed phrase leak", "private key wallet", "mnemonic leaked", "crypto wallet dump"]
            for kw in _KEYWORDS:
                try:
                    await self._rate_limit()
                    url = f"https://api.pullpush.io/reddit/search/submission/?q={kw.replace(' ', '+')}&size=25"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 200:
                        continue
                    for post in resp.json().get("data", []):
                        full_url = f"https://www.reddit.com{post.get('permalink', '')}"
                        if full_url in seen_urls:
                            continue
                        seen_urls.add(full_url)
                        combined = f"{post.get('title', '')}\n{post.get('selftext', '')}".strip()
                        if combined:
                            leaks.append(RawLeak(text=combined, source_name="reddit", source_url=full_url))
                except Exception as exc:
                    logger.error("Reddit keyword '%s' error: %s", kw, exc)

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
