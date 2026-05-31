"""NPM Registry source adapter for crypto leak discovery."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "private key env",
    "mnemonic seed phrase",
    "wallet private key",
    "crypto bot token",
    "web3 private key",
    "ethers wallet key",
    "solana keypair",
    "trading bot secret",
    "sniper bot private key",
    "mev bot key",
    "flashbot private key",
    "defi bot config",
    "hardhat private key",
    "foundry deployer key",
    "anchor wallet key",
]

# npm package names known to be crypto bots/tools that often leak keys
_CRYPTO_PACKAGES = [
    "web3",
    "ethers",
    "solana-web3",
    "@solana/web3.js",
    "hardhat",
    "truffle",
    "ganache",
    "anchor",
]

class NpmSource:
    """Scan NPM registry for leaked crypto keys in package contents."""

    # Multiple registry endpoints for fallback
    REGISTRY_ENDPOINTS = [
        ("npmjs", "https://registry.npmjs.org/-/v1/search", "https://registry.npmjs.org"),
        ("npmmirror", "https://registry.npmmirror.com/-/v1/search", "https://registry.npmmirror.com"),
    ]

    def __init__(self, max_per_query: int = 20, request_delay: float = 1.0, timeout: float = 15.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search NPM for packages with crypto key leaks using multiple registries."""
        leaks: list[RawLeak] = []
        seen_packages: set[str] = set()

        # Try each registry endpoint
        for endpoint_name, search_url, registry_url in self.REGISTRY_ENDPOINTS:
            try:
                result = await asyncio.wait_for(
                    self._search_via_registry(search_url, registry_url, seen_packages),
                    timeout=30,
                )
                leaks.extend(result)
                if leaks:
                    logger.info("NPM: got %d leaks via %s", len(leaks), endpoint_name)
                    break
            except asyncio.TimeoutError:
                logger.debug("NPM %s timed out", endpoint_name)
            except Exception as exc:
                logger.debug("NPM %s error: %s", endpoint_name, exc)

        return leaks

    async def _search_via_registry(self, search_url: str, registry_url: str, seen_packages: set[str]) -> list[RawLeak]:
        """Search via a specific NPM registry."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for query in _QUERIES[:5]:  # Limit queries to avoid timeouts
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        search_url,
                        params={"text": query, "size": self.max_per_query},
                    )
                    if resp.status_code != 200:
                        continue
                    for doc in resp.json().get("objects", []):
                        pkg = doc.get("package", {})
                        pkg_name = pkg.get("name", "")
                        if pkg_name in seen_packages:
                            continue
                        seen_packages.add(pkg_name)
                        pkg_leaks = await self._inspect_package(client, pkg_name, registry_url)
                        leaks.extend(pkg_leaks)
                except Exception as exc:
                    logger.debug("NPM search '%s' error: %s", query, exc)
        return leaks

    async def _inspect_package(self, client: httpx.AsyncClient, pkg_name: str, registry_url: str = "https://registry.npmjs.org") -> list[RawLeak]:
        """Fetch a package's README and look for leaked keys."""
        leaks: list[RawLeak] = []
        try:
            await self._rate_limit()
            resp = await client.get(f"{registry_url}/{pkg_name}")
            if resp.status_code != 200:
                return leaks
            data = resp.json()
            readme = data.get("readme", "")
            if readme:
                leaks.append(RawLeak(
                    text=readme,
                    source_name="npm_readme",
                    source_url=f"https://www.npmjs.com/package/{pkg_name}",
                ))
            # Check latest version's dist files for .env-like content
            latest = data.get("dist-tags", {}).get("latest", "")
            if latest:
                version_data = data.get("versions", {}).get(latest, {})
                # Check if package has suspicious files in its tarball
                # We can't easily fetch tarballs, but we can check the package.json
                # for scripts that might reference .env files
                scripts = version_data.get("scripts", {})
                for script_name, script_cmd in scripts.items():
                    if any(kw in str(script_cmd).lower() for kw in ["private", "key", "mnemonic", "seed", "wallet", "secret"]):
                        leaks.append(RawLeak(
                            text=f"Package {pkg_name} script '{script_name}': {script_cmd}",
                            source_name="npm_script",
                            source_url=f"https://www.npmjs.com/package/{pkg_name}",
                        ))
        except Exception as exc:
            logger.debug("NPM inspect '%s' error: %s", pkg_name, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search NPM for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for endpoint_name, search_url, registry_url in self.REGISTRY_ENDPOINTS:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        search_url,
                        params={"text": f'"{address}"', "size": 10},
                    )
                    if resp.status_code == 200:
                        for doc in resp.json().get("objects", []):
                            pkg = doc.get("package", {})
                            pkg_name = pkg.get("name", "")
                            if pkg_name:
                                pkg_leaks = await self._inspect_package(client, pkg_name, registry_url)
                                leaks.extend(pkg_leaks)
                    if leaks:
                        break
                except Exception as exc:
                    logger.debug("NPM %s address search error: %s", endpoint_name, exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
