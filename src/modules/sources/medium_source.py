"""Medium keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://{username}.medium.com/`` — public profile subdomain. The
  ``@username`` path is Cloudflare-challenged for non-browser clients,
  so this adapter queries the subdomain instead. Soft-404 pages ("PAGE
  NOT FOUND") and Cloudflare challenges are treated as misses.

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

# Medium usernames: 3-30 chars, start alphanumeric, may contain dashes.
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,29}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_DESC_PREFIX = "Read writing from "


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


class MediumSource:
    """Keyless username -> public Medium profile leaks."""

    BASE_URL = "https://medium.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Medium profile leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"https://{username}.medium.com/"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code in (403, 410):
                    return []
                if resp.status_code != 200:
                    return []
                if "PAGE NOT FOUND" in resp.text or "Out of nothing, something." in resp.text:
                    return []
                if resp.headers.get("cf-mitigated") == "challenge":
                    logger.debug("medium Cloudflare challenge for %s", username)
                    return []
                description = _meta_description(resp.text)
                if not description or not description.startswith(_DESC_PREFIX):
                    return []
                rest = description[len(_DESC_PREFIX) :]
                name, sep, bio = rest.partition(" on Medium.")
                leaks.append(
                    RawLeak(
                        text=f"medium: {username}"[:_MAX_TEXT],
                        source_name="medium",
                        source_url=source_url,
                    )
                )
                if sep and name and name != username:
                    leaks.append(
                        RawLeak(
                            text=f"profile title: {name}"[:_MAX_TEXT],
                            source_name="medium",
                            source_url=source_url,
                        )
                    )
                if bio:
                    leaks.append(
                        RawLeak(
                            text=f"description: {bio}"[:_MAX_TEXT],
                            source_name="medium",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("medium error for %s: %s", username, exc)
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
