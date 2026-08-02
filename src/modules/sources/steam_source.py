"""Steam keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://steamcommunity.com/id/{username}/?xml=1`` — public XML profile
  feed. Existing users return HTTP 200 with a ``<profile>`` document;
  unknown users ALSO return HTTP 200 but the body contains ``<error>``,
  which this adapter treats as a miss.

Transport: plain XML fetch (0-API priority tier RE). Honors
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

# Steam custom URL ids: 2-32 chars, start alphanumeric, may contain
# dashes and underscores.
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}


def _xml_text(body: str, tag: str) -> str | None:
    """Extract and unescape a single XML tag body, or None."""
    match = re.search(rf"<{tag}>(.*?)</{tag}>", body, re.DOTALL | re.IGNORECASE)
    if not match:
        return None
    value = match.group(1)
    cdata = re.search(r"<!\[CDATA\[(.*)\]\]>", value, re.DOTALL)
    if cdata:
        value = cdata.group(1)
    value = html.unescape(value).strip()
    return value or None


class SteamSource:
    """Keyless username -> public Steam profile leaks."""

    BASE_URL = "https://steamcommunity.com"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Steam profile leaks."""
        username = address.strip().lower()
        if not self._looks_like_username(username):
            return []
        leaks: list[RawLeak] = []
        source_url = f"{self.BASE_URL}/id/{username}/?xml=1"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, headers=_HEADERS) as client:
            try:
                await self._rate_limit()
                resp = await client.get(source_url)
                if resp.status_code != 200:
                    return []
                # Unknown users return 200 with an <error> body instead of 404.
                if _xml_text(resp.text, "error") is not None:
                    return []
                personaname = _xml_text(resp.text, "personaname")
                if personaname is None:
                    return []
                leaks.append(
                    RawLeak(
                        text=f"steam: {username}"[:_MAX_TEXT],
                        source_name="steam",
                        source_url=source_url,
                    )
                )
                if personaname and personaname != username:
                    leaks.append(
                        RawLeak(
                            text=f"display name: {personaname}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                steam_id = _xml_text(resp.text, "steamID64")
                if steam_id:
                    leaks.append(
                        RawLeak(
                            text=f"steam64 id: {steam_id}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                member_since = _xml_text(resp.text, "memberSince")
                if member_since:
                    leaks.append(
                        RawLeak(
                            text=f"member since: {member_since}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                realname = _xml_text(resp.text, "realname")
                if realname:
                    leaks.append(
                        RawLeak(
                            text=f"real name: {realname}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                location = _xml_text(resp.text, "location")
                if location:
                    leaks.append(
                        RawLeak(
                            text=f"location: {location}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                summary = _xml_text(resp.text, "summary")
                if summary:
                    leaks.append(
                        RawLeak(
                            text=f"summary: {summary}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                vac_banned = _xml_text(resp.text, "vacBanned")
                if vac_banned == "1":
                    leaks.append(
                        RawLeak(
                            text="vac banned: 1"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
                trade_ban = _xml_text(resp.text, "tradeBanState")
                if trade_ban and trade_ban != "None":
                    leaks.append(
                        RawLeak(
                            text=f"trade ban: {trade_ban}"[:_MAX_TEXT],
                            source_name="steam",
                            source_url=source_url,
                        )
                    )
            except Exception as exc:
                logger.debug("steam error for %s: %s", username, exc)
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
