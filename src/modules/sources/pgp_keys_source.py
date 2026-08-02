"""PGP key discovery source adapter — keyless keys.openpgp.org VKS.

Reverse-engineered / keyless public endpoint (no API key required):
``https://keys.openpgp.org/vks/v1/by-email/<sha1-hex>``

The VKS by-email lookup takes the SHA-1 hash (hex) of the lowercased email
address to prevent harvesting. Returns the ASCII-armored public key when a
matching key is published, 404 otherwise.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_MAX_TEXT = 10_000


class PgpKeysSource:
    """Keyless PGP public-key discovery via keys.openpgp.org."""

    BASE_URL = "https://keys.openpgp.org/vks/v1"

    def __init__(self, request_delay: float = 2.0, timeout: float = 30.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Adapter contract: no global feed; return empty."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Look up the public PGP key(s) published for an email address."""
        leaks: list[RawLeak] = []
        email = address.strip().lower()
        if not email or "@" not in email:
            return []
        # VKS protocol mandates SHA-1 of the lowercase address as lookup key.
        digest = hashlib.sha1(email.encode("utf-8"), usedforsecurity=False).hexdigest()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{self.BASE_URL}/by-email/{digest}")
                if resp.status_code == 200 and resp.text.strip():
                    body = resp.text.strip()
                    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in body:
                        leaks.append(
                            RawLeak(
                                text=body[:_MAX_TEXT],
                                source_name="pgp_keys",
                                source_url=f"https://keys.openpgp.org/search?q={email}",
                            )
                        )
            except Exception as exc:
                logger.debug("pgp_keys error for %s: %s", email, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
