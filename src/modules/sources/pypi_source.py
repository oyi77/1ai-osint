"""PyPI source adapter for finding leaked keys in Python packages."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "private key env",
    "mnemonic seed",
    "wallet config",
    "api key secret",
    "credentials json",
    "web3 private",
    "solana keypair",
    "ethers wallet",
    "trading bot",
    "crypto bot",
]

class PypiSource:
    """Scan PyPI for packages with leaked crypto keys."""

    BASE_URL = "https://pypi.org"

    def __init__(self, max_per_query: int = 20, request_delay: float = 1.0, timeout: float = 15.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search PyPI for packages with crypto key leaks."""
        leaks: list[RawLeak] = []
        seen_packages: set[str] = set()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for query in _QUERIES[:5]:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/search/",
                        params={"q": query, "o": "created"},
                    )
                    if resp.status_code == 200:
                        import re
                        # Extract package names from search results
                        packages = re.findall(r'/project/([^/"]+)/', resp.text)
                        for pkg in packages[:self.max_per_query]:
                            if pkg in seen_packages:
                                continue
                            seen_packages.add(pkg)
                            pkg_leaks = await self._inspect_package(client, pkg)
                            leaks.extend(pkg_leaks)
                except Exception as exc:
                    logger.debug("PyPI search '%s' error: %s", query, exc)
        return leaks

    async def _inspect_package(self, client: httpx.AsyncClient, pkg_name: str) -> list[RawLeak]:
        """Fetch a package's description and look for leaked keys."""
        leaks: list[RawLeak] = []
        try:
            await self._rate_limit()
            resp = await client.get(f"{self.BASE_URL}/pypi/{pkg_name}/json")
            if resp.status_code != 200:
                return leaks
            data = resp.json()
            info = data.get("info", {})
            description = info.get("description", "")
            if description:
                leaks.append(RawLeak(
                    text=description,
                    source_name="pypi",
                    source_url=f"https://pypi.org/project/{pkg_name}/",
                ))
        except Exception as exc:
            logger.debug("PyPI inspect '%s' error: %s", pkg_name, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search PyPI for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(f"{self.BASE_URL}/pypi/{address}/json")
                if resp.status_code == 200:
                    data = resp.json()
                    description = data.get("info", {}).get("description", "")
                    if description:
                        leaks.append(RawLeak(
                            text=description,
                            source_name="pypi",
                            source_url=f"https://pypi.org/project/{address}/",
                        ))
            except Exception as exc:
                logger.debug("PyPI address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
