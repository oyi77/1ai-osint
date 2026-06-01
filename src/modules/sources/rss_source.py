"""RSS feed source adapter for monitoring security feeds."""
from __future__ import annotations
import asyncio
import logging
import re
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_FEEDS = [
    ("https://feeds.feedburner.com/TheHackersNews", "thehackernews"),
    ("https://krebsonsecurity.com/feed/", "krebsonsecurity"),
    ("https://www.bleepingcomputer.com/feed/", "bleepingcomputer"),
    ("https://threatpost.com/feed/", "threatpost"),
    ("https://blog.malwarebytes.com/feed/", "malwarebytes"),
]


class RSSSource:
    """Monitor RSS feeds for crypto-related security news."""

    def __init__(self, request_delay: float = 2.0, timeout: float = 15.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Fetch recent entries from security RSS feeds."""
        leaks: list[RawLeak] = []
        crypto_keywords = ["crypto", "wallet", "private key", "mnemonic", "bitcoin", "ethereum", "blockchain", "defi", "token"]

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for feed_url, feed_name in _FEEDS:
                try:
                    await self._rate_limit()
                    resp = await client.get(feed_url)
                    if resp.status_code == 200:
                        items = re.findall(r'<item>(.*?)</item>', resp.text, re.DOTALL)
                        for item in items[:5]:
                            title = re.search(r'<title>(.*?)</title>', item, re.DOTALL)
                            link = re.search(r'<link>(.*?)</link>', item, re.DOTALL)
                            desc = re.search(r'<description>(.*?)</description>', item, re.DOTALL)
                            if title and link:
                                title_text = title.group(1).strip()
                                link_text = link.group(1).strip()
                                desc_text = desc.group(1).strip() if desc else ""
                                combined = f"{title_text} {desc_text}".lower()
                                if any(kw in combined for kw in crypto_keywords):
                                    leaks.append(RawLeak(
                                        text=f"Title: {title_text}\n{desc_text[:2000]}",
                                        source_name=f"rss_{feed_name}",
                                        source_url=link_text,
                                    ))
                except Exception as exc:
                    logger.debug("RSS feed %s error: %s", feed_name, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search RSS feeds for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for feed_url, feed_name in _FEEDS:
                try:
                    await self._rate_limit()
                    resp = await client.get(feed_url)
                    if resp.status_code == 200 and address.lower() in resp.text.lower():
                        leaks.append(RawLeak(
                            text=f"Address {address} found in {feed_name} feed",
                            source_name=f"rss_{feed_name}",
                            source_url=feed_url,
                        ))
                except Exception:
                    pass
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
