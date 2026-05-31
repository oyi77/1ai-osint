"""Social media source adapter for OSINT across platforms."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class SocialSource:
    """Scan social media platforms for user information."""

    # Public API endpoints that don't require auth
    ENDPOINTS = {
        "github_user": "https://api.github.com/users/{username}",
        "gitlab_user": "https://gitlab.com/api/v4/users?username={username}",
        "reddit_user": "https://www.reddit.com/user/{username}/about.json",
        "keybase": "https://keybase.io/_/api/1.0/user/lookup.json?username={username}",
    }

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Social media requires a username target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search social media platforms for a username."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "1ai-osint/0.1.0"},
        ) as client:
            for platform, url_template in self.ENDPOINTS.items():
                try:
                    await self._rate_limit()
                    url = url_template.format(username=address)
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data:
                            leaks.append(RawLeak(
                                text=str(data)[:10000],
                                source_name=f"social_{platform}",
                                source_url=url,
                            ))
                except Exception as exc:
                    logger.debug("Social %s error for '%s': %s", platform, address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
