"""Chess.com keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://www.chess.com/member/{username}`` — public member profile page.
  Returns HTTP 200 for existing members and 404 for unknown ones; the
  page embeds profile-card fields (title, full name, location, joined).

ToS caveat: Chess.com's Terms of Service restrict automated scraping.
This adapter is rate-limited (``request_delay``) and reads only the
public profile page; users of this adapter should keep requests minimal
and comply with the platform ToS.

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

# Chess.com usernames: 3-20 chars, start/end alphanumeric, may contain
# dashes and underscores in between.
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,18}[a-z0-9]$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}


def _class_text(body: str, class_fragment: str) -> str | None:
    """Extract visible text from the first element whose class contains a fragment."""
    pattern = re.compile(r'class="[^"]*' + re.escape(class_fragment) + r'[^"]*"[^>]*>(.*?)</', re.DOTALL)
    match = pattern.search(body)
    if not match:
        return None
    value = re.sub(r"<[^>]+>", "", match.group(1))
    value = re.sub(r"\s+", " ", value).strip()
    return value or None


class ChessSource:
    """Keyless username -> public Chess.com member profile leaks."""

    BASE_URL = "https://www.chess.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Chess.com member profile leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/member/{username}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"chess: {username}"[:_MAX_TEXT],
                        source_name="chess",
                        source_url=source_url,
                    )
                )
                title = _class_text(resp.text, "cc-user-title-component")
                if title:
                    leaks.append(
                        RawLeak(
                            text=f"chess title: {title}"[:_MAX_TEXT],
                            source_name="chess",
                            source_url=source_url,
                        )
                    )
                full_name = _class_text(resp.text, "profile-card-name")
                if full_name:
                    leaks.append(
                        RawLeak(
                            text=f"full name: {full_name}"[:_MAX_TEXT],
                            source_name="chess",
                            source_url=source_url,
                        )
                    )
                location = _class_text(resp.text, "profile-card-location")
                if location:
                    leaks.append(
                        RawLeak(
                            text=f"location: {location}"[:_MAX_TEXT],
                            source_name="chess",
                            source_url=source_url,
                        )
                    )
                joined = _class_text(resp.text, "profile-header-details-value")
                if joined:
                    leaks.append(
                        RawLeak(
                            text=f"joined: {joined}"[:_MAX_TEXT],
                            source_name="chess",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("chess error for %s: %s", username, exc)
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
