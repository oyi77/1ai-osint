"""Pastebin keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://pastebin.com/u/{username}`` — public user page. Returns HTTP
  200 for existing users and 404 for unknown ones; the page embeds the
  profile name and the user's latest paste dates.

Case note: Pastebin usernames are case-preserving, so unlike most other
username adapters this one does NOT lowercase the input — it queries the
username exactly as given.

ToS caveat: Pastebin's Terms of Service restrict automated scraping.
This adapter is rate-limited (``request_delay``) and reads only the
public user page; users of this adapter should keep requests minimal and
comply with the platform ToS.

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

# Pastebin usernames: 2-30 chars, letters, digits and underscores.
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{2,30}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_JOINED_RE = re.compile(r'class="[^"]*date-text[^"]*"[^>]*title="([^"]+)"')


def _class_text(body: str, class_fragment: str) -> str | None:
    """Extract visible text from the first element whose class contains a fragment."""
    pattern = re.compile(r'class="[^"]*' + re.escape(class_fragment) + r'[^"]*"[^>]*>(.*?)</', re.DOTALL)
    match = pattern.search(body)
    if not match:
        return None
    value = re.sub(r"<[^>]+>", "", match.group(1))
    value = re.sub(r"\s+", " ", value).strip()
    return value or None


class PastebinSource:
    """Keyless username -> public Pastebin user-page leaks."""

    BASE_URL = "https://pastebin.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Pastebin user-page leaks."""
        # Intentional deviation: Pastebin usernames are case-preserving, so
        # the address is NOT lowercased here.
        username = address.strip()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/u/{username}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"pastebin: {username}"[:_MAX_TEXT],
                        source_name="pastebin",
                        source_url=source_url,
                    )
                )
                title_match = _TITLE_RE.search(resp.text)
                if title_match:
                    title = title_match.group(1).strip()
                    if title.endswith(" - Pastebin.com"):
                        title = title[: -len(" - Pastebin.com")].strip()
                    if title.endswith("'s Pastebin"):
                        title = title[: -len("'s Pastebin")].strip()
                    if title and title != username:
                        leaks.append(
                            RawLeak(
                                text=f"profile title: {title}"[:_MAX_TEXT],
                                source_name="pastebin",
                                source_url=source_url,
                            )
                        )
                joined = _class_text(resp.text, "date-text")
                if not joined:
                    joined_match = _JOINED_RE.search(resp.text)
                    if joined_match:
                        joined = joined_match.group(1).strip()
                if joined:
                    leaks.append(
                        RawLeak(
                            text=f"joined: {joined}"[:_MAX_TEXT],
                            source_name="pastebin",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("pastebin error for %s: %s", username, exc)
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
