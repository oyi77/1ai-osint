"""Reddit source adapter for crypto leak discovery."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

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
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "crypto-leak-scanner/1.0"}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for sub in _SUBREDDITS:
                try:
                    await self._rate_limit()
                    url = f"https://www.reddit.com/r/{sub}/new.json?limit={self.max_per_sub}"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 200:
                        logger.debug("Reddit r/%s returned %d", sub, resp.status_code)
                        continue
                    data = resp.json()
                    for post in data.get("data", {}).get("children", []):
                        post_data = post.get("data", {})
                        title = post_data.get("title", "")
                        selftext = post_data.get("selftext", "")
                        permalink = post_data.get("permalink", "")
                        full_url = f"https://www.reddit.com{permalink}" if permalink else ""
                        # Combine title + body for extraction
                        combined = f"{title}\n{selftext}".strip()
                        if combined:
                            leaks.append(RawLeak(text=combined, source_name="reddit", source_url=full_url))
                except Exception as exc:
                    logger.error("Reddit r/%s error: %s", sub, exc)
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
