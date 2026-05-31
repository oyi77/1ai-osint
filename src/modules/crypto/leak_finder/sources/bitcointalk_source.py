"""BitcoinTalk forum scanner for crypto leak discovery.

Scrapes BitcoinTalk.org board pages for posts containing leaked keys/mnemonics.
Many early Bitcoin users accidentally posted private keys in forum discussions.
"""
from __future__ import annotations
import asyncio
import logging
import time
from bs4 import BeautifulSoup
import httpx
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

logger = logging.getLogger(__name__)

# Boards to scan — wallet recovery, key management, and altcoin discussions
_BOARDS = [
    ("https://bitcointalk.org/index.php?board=4.0", "Wallet software"),  # Wallet software
    ("https://bitcointalk.org/index.php?board=1.0", "Bitcoin discussion"),
    ("https://bitcointalk.org/index.php?board=67.0", "Wallet recovery"),
    ("https://bitcointalk.org/index.php?board=159.0", "Bounties"),
]


class BitcoinTalkSource:
    """Scan BitcoinTalk forum for leaked crypto keys/mnemonics."""

    def __init__(self, max_topics: int = 10, request_delay: float = 3.0, timeout: float = 30.0):
        self.max_topics = max_topics
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        leaks: list[RawLeak] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for board_url, _ in _BOARDS:
                try:
                    await self._rate_limit()
                    resp = await client.get(board_url, headers=headers)
                    if resp.status_code != 200:
                        continue
                    soup = BeautifulSoup(resp.text, "html.parser")
                    # Find topic links
                    topic_links = []
                    for a in soup.find_all("a", href=True):
                        href = a.get("href", "")
                        if "topic=" in href and href.startswith("http"):
                            topic_links.append(href)
                    topic_links = list(dict.fromkeys(topic_links))[:self.max_topics]

                    for topic_url in topic_links:
                        try:
                            await self._rate_limit()
                            tresp = await client.get(topic_url, headers=headers)
                            if tresp.status_code != 200:
                                continue
                            tsoup = BeautifulSoup(tresp.text, "html.parser")
                            # Extract post bodies
                            for post_div in tsoup.find_all("div", class_="post"):
                                text = post_div.get_text(separator=" ", strip=True)
                                if len(text) > 20:
                                    leaks.append(RawLeak(text=text, source_name="bitcointalk", source_url=topic_url))
                        except Exception:
                            pass
                except Exception as exc:
                    logger.error("BitcoinTalk error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
