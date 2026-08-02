"""Fandom keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://community.fandom.com/api.php`` — MediaWiki ``action=query``
  list=users API. Public and keyless; returns user id, registration date,
  edit count, groups and gender for existing users, or a ``missing``
  entry for unknown ones.

Transport: keyless JSON API fetch (0-API priority tier RE — keyless
endpoint reverse-engineered without an API key). Honors
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

# MediaWiki usernames: 1-64 chars, letters, digits and underscores.
_USERNAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_API_PARAMS = {
    "action": "query",
    "list": "users",
    "usprop": "blockinfo|groups|editcount|registration|gender",
    "format": "json",
}


class FandomSource:
    """Keyless username -> public Fandom user leaks."""

    BASE_URL = "https://community.fandom.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Fandom user leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/api.php"
        params = dict(_API_PARAMS, ususers=username)
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url, params=params)
                if resp.status_code != 200:
                    return []
                try:
                    payload = resp.json()
                except ValueError:
                    return []
                users = payload.get("query", {}).get("users", [])
                if not users:
                    return []
                user = users[0]
                if "missing" in user:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"fandom: {username}"[:_MAX_TEXT],
                        source_name="fandom",
                        source_url=source_url,
                    )
                )
                userid = user.get("userid")
                if userid:
                    leaks.append(
                        RawLeak(
                            text=f"fandom user id: {userid}"[:_MAX_TEXT],
                            source_name="fandom",
                            source_url=source_url,
                        )
                    )
                registration = user.get("registration")
                if registration:
                    leaks.append(
                        RawLeak(
                            text=f"registered: {str(registration)[:10]}"[:_MAX_TEXT],
                            source_name="fandom",
                            source_url=source_url,
                        )
                    )
                editcount = user.get("editcount")
                if editcount is not None:
                    leaks.append(
                        RawLeak(
                            text=f"edit count: {editcount}"[:_MAX_TEXT],
                            source_name="fandom",
                            source_url=source_url,
                        )
                    )
                groups = user.get("groups", [])
                if groups:
                    leaks.append(
                        RawLeak(
                            text=f"groups: {', '.join(groups)}"[:_MAX_TEXT],
                            source_name="fandom",
                            source_url=source_url,
                        )
                    )
                gender = user.get("gender")
                if gender and gender != "unknown":
                    leaks.append(
                        RawLeak(
                            text=f"gender: {gender}"[:_MAX_TEXT],
                            source_name="fandom",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("fandom error for %s: %s", username, exc)
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
