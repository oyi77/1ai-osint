"""Go modules source adapter for finding leaked keys in Go packages."""

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
    "crypto bot",
    "web3",
]


class GomodSource:
    """Scan pkg.go.dev for Go modules with leaked crypto keys."""

    BASE_URL = "https://pkg.go.dev"

    def __init__(
        self, max_per_query: int = 15, request_delay: float = 2.0, timeout: float = 15.0
    ):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search pkg.go.dev for Go modules with crypto key leaks."""
        leaks: list[RawLeak] = []
        seen_modules: set[str] = set()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for query in _QUERIES[:3]:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/search",
                        params={"q": query, "m": "package"},
                    )
                    if resp.status_code == 200:
                        import re

                        # Extract module paths from search results
                        modules = re.findall(r'href="/([^"]+)"', resp.text)
                        for mod in modules[: self.max_per_query]:
                            if mod in seen_modules or mod.startswith("@"):
                                continue
                            seen_modules.add(mod)
                            mod_leaks = await self._inspect_module(client, mod)
                            leaks.extend(mod_leaks)
                except Exception as exc:
                    logger.debug("Go modules search '%s' error: %s", query, exc)
        return leaks

    async def _inspect_module(
        self, client: httpx.AsyncClient, module_path: str
    ) -> list[RawLeak]:
        """Fetch a Go module's documentation."""
        leaks: list[RawLeak] = []
        try:
            await self._rate_limit()
            resp = await client.get(f"{self.BASE_URL}/{module_path}")
            if resp.status_code == 200:
                text = resp.text[:50000]
                if text.strip():
                    leaks.append(
                        RawLeak(
                            text=text,
                            source_name="gomod",
                            source_url=f"https://pkg.go.dev/{module_path}",
                        )
                    )
        except Exception as exc:
            logger.debug("Go module '%s' error: %s", module_path, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search pkg.go.dev for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/search",
                    params={"q": address},
                )
                if resp.status_code == 200:
                    leaks.append(
                        RawLeak(
                            text=resp.text[:50000],
                            source_name="gomod",
                            source_url=f"https://pkg.go.dev/search?q={address}",
                        )
                    )
            except Exception as exc:
                logger.debug("Go modules address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
