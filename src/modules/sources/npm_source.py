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

    SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
    REGISTRY_URL = "https://registry.npmjs.org"

    def __init__(self, max_per_query: int = 50, request_delay: float = 1.0, timeout: float = 30.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search NPM for packages with crypto key leaks in their published files."""
        leaks: list[RawLeak] = []
        seen_packages: set[str] = set()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # 1. Search by queries
            for query in _QUERIES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        self.SEARCH_URL,
                        params={"text": query, "size": min(self.max_per_query, 250)},
                    )
                    if resp.status_code != 200:
                        logger.debug("NPM search '%s' returned %d", query, resp.status_code)
                        continue
                    for doc in resp.json().get("objects", []):
                        pkg = doc.get("package", {})
                        pkg_name = pkg.get("name", "")
                        if pkg_name in seen_packages:
                            continue
                        seen_packages.add(pkg_name)
                        # Fetch package details to check for leaked keys
                        pkg_leaks = await self._inspect_package(client, pkg_name)
                        leaks.extend(pkg_leaks)
                except Exception as exc:
                    logger.error("NPM search '%s' error: %s", query, exc)

            # 2. Check known crypto packages' README and files
            for pkg_name in _CRYPTO_PACKAGES:
                if pkg_name in seen_packages:
                    continue
                seen_packages.add(pkg_name)
                try:
                    pkg_leaks = await self._inspect_package(client, pkg_name)
                    leaks.extend(pkg_leaks)
                except Exception as exc:
                    logger.error("NPM package '%s' error: %s", pkg_name, exc)

        return leaks

    async def _inspect_package(self, client: httpx.AsyncClient, pkg_name: str) -> list[RawLeak]:
        """Fetch a package's README and look for leaked keys."""
        leaks: list[RawLeak] = []
        try:
            await self._rate_limit()
            # Fetch package metadata
            resp = await client.get(f"{self.REGISTRY_URL}/{pkg_name}")
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
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.SEARCH_URL,
                    params={"text": f'"{address}"', "size": 50},
                )
                if resp.status_code == 200:
                    for doc in resp.json().get("objects", []):
                        pkg = doc.get("package", {})
                        pkg_name = pkg.get("name", "")
                        pkg_leaks = await self._inspect_package(client, pkg_name)
                        leaks.extend(pkg_leaks)
            except Exception as exc:
                logger.error("NPM address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
