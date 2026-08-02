"""Letterboxd keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://letterboxd.com/{username}/`` — public profile page. Returns
  HTTP 200 for existing users and 404 for unknown ones; the page embeds
  the profile title, description, external links and member-since date.

Transport: plain HTML fetch (0-API priority tier RE). Honors
``request_delay`` between calls and never raises.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000

# Letterboxd usernames: 3-15 chars, start alphanumeric, may contain
# underscores (dashes are NOT allowed).
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_]{2,14}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_EXTERNAL_LINK_RE = re.compile(r'<a[^>]+class="[^"]*external-link[^"]*"[^>]*href="([^"]+)"')
_MEMBER_SINCE_RE = re.compile(r"Member since</span>\s*<span[^>]*>([^<]+)", re.IGNORECASE)


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


class LetterboxdSource:
    """Keyless username -> public Letterboxd profile leaks."""

    BASE_URL = "https://letterboxd.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Letterboxd profile leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/{username}/"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"letterboxd: {username}"[:_MAX_TEXT],
                        source_name="letterboxd",
                        source_url=source_url,
                    )
                )
                title_match = _TITLE_RE.search(resp.text)
                if title_match:
                    title = title_match.group(1).strip()
                    if title.endswith("'s profile • Letterboxd"):
                        title = title[: -len("'s profile • Letterboxd")].strip()
                    if title and title != username:
                        leaks.append(
                            RawLeak(
                                text=f"profile title: {title}"[:_MAX_TEXT],
                                source_name="letterboxd",
                                source_url=source_url,
                            )
                        )
                description = _meta_description(resp.text)
                if description:
                    leaks.append(
                        RawLeak(
                            text=f"description: {description}"[:_MAX_TEXT],
                            source_name="letterboxd",
                            source_url=source_url,
                        )
                    )
                for link in _EXTERNAL_LINK_RE.findall(resp.text):
                    leaks.append(
                        RawLeak(
                            text=f"external link: {html.unescape(link)}"[:_MAX_TEXT],
                            source_name="letterboxd",
                            source_url=source_url,
                        )
                    )
                member_since = _MEMBER_SINCE_RE.search(resp.text)
                if member_since:
                    leaks.append(
                        RawLeak(
                            text=f"member since: {member_since.group(1).strip()}"[:_MAX_TEXT],
                            source_name="letterboxd",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("letterboxd error for %s: %s", username, exc)
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
