"""DEV Community (dev.to) keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://dev.to/{username}`` — public profile page. Returns HTTP 200
  for existing users and 404 for unknown ones; the page embeds a
  JSON-LD ``sameAs`` list with linked social profiles.

Transport: plain HTML fetch (0-API priority tier RE). Honors
``request_delay`` between calls and never raises.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000

# DEV usernames: 2-30 chars, lowercase letters, digits, dashes and underscores.
_USERNAME_RE = re.compile(r"^[a-z0-9_-]{2,30}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_TIME_RE = re.compile(r'<time datetime="([^"]+)">', re.IGNORECASE)
_SAME_AS_RE = re.compile(r'"sameAs"\s*:\s*(\[[^\]]*\])', re.DOTALL)


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


class DevToSource:
    """Keyless username -> public DEV Community profile leaks."""

    BASE_URL = "https://dev.to"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public DEV Community profile leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/{username}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"devto: {username}"[:_MAX_TEXT],
                        source_name="devto",
                        source_url=source_url,
                    )
                )
                title_match = _TITLE_RE.search(resp.text)
                if title_match:
                    title = title_match.group(1).strip()
                    if title.endswith(" - DEV Community"):
                        title = title[: -len(" - DEV Community")].strip()
                    if title and title != username:
                        leaks.append(
                            RawLeak(
                                text=f"profile title: {title}"[:_MAX_TEXT],
                                source_name="devto",
                                source_url=source_url,
                            )
                        )
                description = _meta_description(resp.text)
                if description:
                    leaks.append(
                        RawLeak(
                            text=f"description: {description}"[:_MAX_TEXT],
                            source_name="devto",
                            source_url=source_url,
                        )
                    )
                time_match = _TIME_RE.search(resp.text)
                if time_match:
                    leaks.append(
                        RawLeak(
                            text=f"joined: {time_match.group(1).strip()}"[:_MAX_TEXT],
                            source_name="devto",
                            source_url=source_url,
                        )
                    )
                same_as_match = _SAME_AS_RE.search(resp.text)
                if same_as_match:
                    try:
                        links = json.loads(same_as_match.group(1))
                    except json.JSONDecodeError:
                        links = []
                    for link in links:
                        if isinstance(link, str) and link.startswith("http"):
                            leaks.append(
                                RawLeak(
                                    text=f"social link: {link}"[:_MAX_TEXT],
                                    source_name="devto",
                                    source_url=source_url,
                                )
                            )
            except Exception as exc:
                logger.debug("devto error for %s: %s", username, exc)
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
