"""Cargo (Rust) source adapter for finding leaked keys in Rust packages."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "private key",
    "mnemonic",
    "wallet",
    "secret key",
    "api key",
    "credentials",
]


class CargoSource:
    """Scan crates.io for packages with leaked crypto keys."""

    BASE_URL = "https://crates.io/api/v1"

    def __init__(
        self, max_per_query: int = 20, request_delay: float = 1.0, timeout: float = 15.0
    ):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search crates.io for packages with crypto key leaks."""
        leaks: list[RawLeak] = []
        seen_crates: set[str] = set()
        headers = {"User-Agent": "1ai-osint/0.1.0"}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, headers=headers
        ) as client:
            for query in _QUERIES[:4]:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/crates",
                        params={
                            "q": query,
                            "per_page": self.max_per_query,
                            "sort": "recent-updates",
                        },
                    )
                    if resp.status_code == 200:
                        for crate in resp.json().get("crates", []):
                            crate_name = crate.get("name", "")
                            if crate_name in seen_crates:
                                continue
                            seen_crates.add(crate_name)
                            desc = crate.get("description", "")
                            if desc:
                                leaks.append(
                                    RawLeak(
                                        text=desc,
                                        source_name="cargo",
                                        source_url=f"https://crates.io/crates/{crate_name}",
                                    )
                                )
                except Exception as exc:
                    logger.debug("Cargo search '%s' error: %s", query, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search crates.io for a specific address."""
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "1ai-osint/0.1.0"}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, headers=headers
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/crates",
                    params={"q": address, "per_page": 5},
                )
                if resp.status_code == 200:
                    for crate in resp.json().get("crates", []):
                        desc = crate.get("description", "")
                        if desc:
                            leaks.append(
                                RawLeak(
                                    text=desc,
                                    source_name="cargo",
                                    source_url=f"https://crates.io/crates/{crate.get('name', '')}",
                                )
                            )
            except Exception as exc:
                logger.debug("Cargo address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
