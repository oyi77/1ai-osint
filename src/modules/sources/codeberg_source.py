"""Codeberg source adapter for crypto leak discovery."""
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
    "wallet private",
    "crypto bot key",
    "web3 private key",
    "solana keypair",
    "hardhat deployer",
    "truffle config key",
    "flashbot key",
    "mev bot config",
]

class CodebergSource:
    """Scan Codeberg (Gitea) for leaked crypto keys in code."""

    SEARCH_URL = "https://codeberg.org/api/v1/repos/search"
    CONTENTS_URL = "https://codeberg.org/api/v1/repos/{owner}/{repo}/contents"

    def __init__(self, max_per_query: int = 20, request_delay: float = 2.0, timeout: float = 30.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search Codeberg for repos with crypto key leaks."""
        leaks: list[RawLeak] = []
        seen_repos: set[str] = set()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for query in _QUERIES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        self.SEARCH_URL,
                        params={
                            "q": query,
                            "limit": self.max_per_query,
                            "sort": "updated",
                            "order": "desc",
                        },
                    )
                    if resp.status_code != 200:
                        logger.debug("Codeberg search '%s' returned %d", query, resp.status_code)
                        continue
                    data = resp.json()
                    for repo in data.get("data", []):
                        repo_full_name = repo.get("full_name", "")
                        if repo_full_name in seen_repos:
                            continue
                        seen_repos.add(repo_full_name)
                        # Fetch repo README and .env files
                        repo_leaks = await self._inspect_repo(client, repo_full_name)
                        leaks.extend(repo_leaks)
                except Exception as exc:
                    logger.error("Codeberg search '%s' error: %s", query, exc)

        return leaks

    async def _inspect_repo(self, client: httpx.AsyncClient, repo_full_name: str) -> list[RawLeak]:
        """Fetch a repo's .env and config files for leaked keys."""
        leaks: list[RawLeak] = []
        base_url = self.CONTENTS_URL.format(
            owner=repo_full_name.split("/")[0],
            repo=repo_full_name.split("/")[1],
        )
        # Files to check for crypto key leaks
        suspicious_files = [
            ".env",
            ".env.example",
            ".env.local",
            ".env.development",
            ".env.production",
            "config.json",
            "config.js",
            "config.ts",
            "hardhat.config.js",
            "hardhat.config.ts",
            "truffle-config.js",
            "foundry.toml",
            "docker-compose.yml",
            "docker-compose.yaml",
            "wallet.json",
            "keystore.json",
        ]
        for filename in suspicious_files:
            try:
                await self._rate_limit()
                resp = await client.get(f"{base_url}/{filename}")
                if resp.status_code != 200:
                    continue
                data = resp.json()
                # Gitea returns file content as base64 or direct text
                content = data.get("content", "")
                encoding = data.get("encoding", "")
                if encoding == "base64":
                    import base64
                    try:
                        content = base64.b64decode(content).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                if content and content.strip():
                    leaks.append(RawLeak(
                        text=content,
                        source_name="codeberg",
                        source_url=f"https://codeberg.org/{repo_full_name}/src/branch/main/{filename}",
                    ))
            except Exception as exc:
                logger.debug("Codeberg file '%s/%s' error: %s", repo_full_name, filename, exc)

        # Also try to fetch README
        for readme_name in ["README.md", "README.rst", "README.txt", "README"]:
            try:
                await self._rate_limit()
                resp = await client.get(f"{base_url}/{readme_name}")
                if resp.status_code != 200:
                    continue
                data = resp.json()
                content = data.get("content", "")
                encoding = data.get("encoding", "")
                if encoding == "base64":
                    import base64
                    try:
                        content = base64.b64decode(content).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                if content and content.strip():
                    leaks.append(RawLeak(
                        text=content,
                        source_name="codeberg_readme",
                        source_url=f"https://codeberg.org/{repo_full_name}",
                    ))
                    break  # Only fetch one README
            except Exception:
                pass

        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Codeberg for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.SEARCH_URL,
                    params={"q": f'"{address}"', "limit": 20},
                )
                if resp.status_code == 200:
                    for repo in resp.json().get("data", []):
                        repo_full_name = repo.get("full_name", "")
                        repo_leaks = await self._inspect_repo(client, repo_full_name)
                        leaks.extend(repo_leaks)
            except Exception as exc:
                logger.error("Codeberg address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
