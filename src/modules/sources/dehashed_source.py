"""DeHashed source adapter for credential leak lookup."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class DehashedSource:
    """Query DeHashed for leaked credentials and breach data."""

    BASE_URL = "https://api.dehashed.com/search"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 2.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("DEHASHED_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """DeHashed requires a search target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search DeHashed for leaked credentials."""
        if not self.api_key:
            logger.debug("DeHashed: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        # Support user:pass format
        if ":" in self.api_key:
            username, password = self.api_key.split(":", 1)
            auth = (username, password)
        else:
            auth = (self.api_key, "")

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.BASE_URL,
                    params={"query": address},
                    auth=auth,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    entries = data.get("entries", [])
                    for entry in entries:
                        structured: dict[str, str] = {}
                        if isinstance(entry, dict):
                            for field in (
                                "email",
                                "username",
                                "phone",
                                "name",
                                "domain",
                                "password",
                                "hashed_password",
                                "ip_address",
                                "address",
                                "database_name",
                            ):
                                val = entry.get(field, "")
                                if val:
                                    key = (
                                        "password_hash"
                                        if field == "hashed_password"
                                        else (
                                            "breach_name"
                                            if field == "database_name"
                                            else field
                                        )
                                    )
                                    structured[key] = str(val)
                        leaks.append(
                            RawLeak(
                                text=str(entry)[:5000],
                                source_name="dehashed",
                                source_url=f"https://dehashed.com/search?query={address}",
                                metadata=structured,
                            )
                        )
            except Exception as exc:
                logger.debug("DeHashed error for '%s': %s", address, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
