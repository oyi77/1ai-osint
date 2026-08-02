"""YouTube keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://www.youtube.com/@{username}/about?hl=en&gl=US`` — public
  channel about page. Follows the 303 canonical redirect for handles and
  embeds the channel title, description, join date and country in the
  initial page state.

Username note: handles may contain ``_`` and ``.`` which this adapter's
ASCII subset regex does not match; those are intentionally out of scope
for the username identifier type and skipped at the guard stage.

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

# YouTube handles: 3-30 chars, start alphanumeric, may contain dashes.
# (ASCII subset — misses `_` and `.`, intentionally commented above.)
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,29}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_JOINED_RE = re.compile(r'"joinedDateText":\{"content":"([^"]+)"\}')
_COUNTRY_RE = re.compile(r'"country":\{"simpleText":"([^"]+)"\}')


def _meta_description(body: str) -> str | None:
    """Extract the page ``meta[name|property=description|og:description]``."""
    patterns = (
        re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL),
        re.compile(r'<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']', re.IGNORECASE | re.DOTALL),
        re.compile(
            r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL
        ),
        re.compile(
            r'<meta[^>]+content=["\'](.*?)["\'][^>]+property=["\']og:description["\']', re.IGNORECASE | re.DOTALL
        ),
    )
    for pattern in patterns:
        match = pattern.search(body)
        if match:
            value = match.group(1).strip()
            if value:
                return value
    return None


class YoutubeSource:
    """Keyless username -> public YouTube channel leaks."""

    BASE_URL = "https://www.youtube.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public YouTube channel leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/@{username}/about?hl=en&gl=US"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                if "404 Not Found" in resp.text:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"youtube: {username}"[:_MAX_TEXT],
                        source_name="youtube",
                        source_url=source_url,
                    )
                )
                title_match = _TITLE_RE.search(resp.text)
                if title_match:
                    title = title_match.group(1).strip()
                    if title.endswith(" - YouTube"):
                        title = title[: -len(" - YouTube")].strip()
                    if title and title != username:
                        leaks.append(
                            RawLeak(
                                text=f"profile title: {title}"[:_MAX_TEXT],
                                source_name="youtube",
                                source_url=source_url,
                            )
                        )
                description = _meta_description(resp.text)
                if description:
                    leaks.append(
                        RawLeak(
                            text=f"description: {description}"[:_MAX_TEXT],
                            source_name="youtube",
                            source_url=source_url,
                        )
                    )
                joined_match = _JOINED_RE.search(resp.text)
                if joined_match:
                    leaks.append(
                        RawLeak(
                            text=f"joined: {joined_match.group(1)}"[:_MAX_TEXT],
                            source_name="youtube",
                            source_url=source_url,
                        )
                    )
                country_match = _COUNTRY_RE.search(resp.text)
                if country_match:
                    leaks.append(
                        RawLeak(
                            text=f"country: {country_match.group(1)}"[:_MAX_TEXT],
                            source_name="youtube",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("youtube error for %s: %s", username, exc)
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
