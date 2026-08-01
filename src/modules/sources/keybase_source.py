"""Keybase keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``/_/api/1.0/user/lookup.json?usernames={username}`` — public Keybase
  profile data: full name, bio, location, site, and avatar.

Honors ``request_delay`` between calls and never raises.
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

_USERNAME_RE = re.compile(r"^[a-z0-9_]{2,16}$")


class KeybaseSource:
    """Keyless username -> public Keybase profile leaks."""

    BASE_URL = "https://keybase.io"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Keybase profile leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/_/api/1.0/user/lookup.json?usernames={username}&fields=basics,profile,pictures"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("status") or {}
                    if status.get("code") != 0:
                        return []
                    them = data.get("them") or []
                    if not them:
                        return []
                    user = them[0]
                    leaks.append(
                        RawLeak(
                            text=f"keybase: {username}"[:_MAX_TEXT],
                            source_name="keybase",
                            source_url=source_url,
                        )
                    )
                    profile = user.get("profile") or {}
                    basics = user.get("basics") or {}
                    for label, value in (
                        ("full name", basics.get("full_name")),
                        ("bio", profile.get("bio")),
                        ("location", profile.get("location")),
                        ("site", profile.get("site")),
                    ):
                        if value:
                            leaks.append(
                                RawLeak(
                                    text=f"{label}: {value}"[:_MAX_TEXT],
                                    source_name="keybase",
                                    source_url=source_url,
                                )
                            )
                    avatar = ((user.get("pictures") or {}).get("primary") or {}).get("url")
                    if avatar:
                        leaks.append(
                            RawLeak(
                                text=f"avatar: {avatar}"[:_MAX_TEXT],
                                source_name="keybase",
                                source_url=source_url,
                            )
                        )
            except Exception as exc:
                logger.debug("keybase error for %s: %s", username, exc)
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
