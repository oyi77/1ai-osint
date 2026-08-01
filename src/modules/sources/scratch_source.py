"""Scratch keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://scratch.mit.edu/users/{username}/`` — public profile page.
  Returns HTTP 200 for existing users and 404 for unknown ones, so a
  single GET discriminates account existence without any key.

Transport: plain HTML fetch (0-API priority tier RE). Honors
``request_delay`` between calls and never raises.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000

# Scratch usernames: 3-20 chars, letters, digits, dashes, underscores.
_USERNAME_RE = re.compile(r"^[a-z0-9_-]{3,20}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}


class ScratchSource:
    """Keyless username -> public Scratch profile presence leaks."""

    BASE_URL = "https://scratch.mit.edu"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Scratch profile presence leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/users/{username}/"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"scratch: {username}"[:_MAX_TEXT],
                        source_name="scratch",
                        source_url=source_url,
                    )
                )
            except Exception as exc:
                logger.debug("scratch error for %s: %s", username, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()

    @staticmethod
    def _looks_like_username(value: str) -> bool:
        return bool(_USERNAME_RE.match(value))
