"""Hugging Face keyless username-lookup source adapter.

Reverse-engineered / keyless public endpoint (no API key required):

- ``https://huggingface.co/{username}`` — public profile page. Returns
  HTTP 200 for existing users and 404 for unknown ones; the page title is
  ``<name> (<full name>)`` for accounts that expose a full name.

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

# Hugging Face usernames: 2-32 chars, start with alphanumeric, may contain
# dashes and underscores.
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

_TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_FULL_NAME_RE = re.compile(r"^(.*?)\s*\(([^)]*)\)\s*$")


class HuggingFaceSource:
    """Keyless username -> public Hugging Face profile leaks."""

    BASE_URL = "https://huggingface.co"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: recent data is not offered keyless; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enrich a username with public Hugging Face profile leaks."""
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
                        text=f"huggingface: {username}"[:_MAX_TEXT],
                        source_name="huggingface",
                        source_url=source_url,
                    )
                )
                title_match = _TITLE_RE.search(resp.text)
                if title_match:
                    title = title_match.group(1).strip()
                    full_match = _FULL_NAME_RE.match(title)
                    if full_match and full_match.group(2).strip():
                        leaks.append(
                            RawLeak(
                                text=f"full name: {full_match.group(2).strip()}"[:_MAX_TEXT],
                                source_name="huggingface",
                                source_url=source_url,
                            )
                        )
                    elif title and title != username:
                        leaks.append(
                            RawLeak(
                                text=f"profile title: {title}"[:_MAX_TEXT],
                                source_name="huggingface",
                                source_url=source_url,
                            )
                        )
            except Exception as exc:
                logger.debug("huggingface error for %s: %s", username, exc)
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
