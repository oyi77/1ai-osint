"""GitHub source adapter for leak finding."""
from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

@dataclass
class RawLeak:
    text: str
    source_name: str
    source_url: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

import random as _random

_QUERIES = [
    # .env files with private keys
    '"PRIVATE_KEY=" filetype:env',
    '"SECRET_KEY=" filetype:env',
    '"PRIVATE_KEY=" "0x" filetype:env',
    '"MNEMONIC=" filetype:env',
    '"WALLET_PRIVATE_KEY" filetype:env',
    '"BOT_TOKEN" "PRIVATE_KEY" filetype:env',
    # Wallet exports
    'filename:keystore.json "ciphertext"',
    'filename:wallet.json "private"',
    '"seed phrase" "12 words"',
    '"bip39 mnemonic" filetype:txt',
    # Config dumps
    '"private_key" "rpc" filetype:json',
    '"mnemonic" "derivation" filetype:txt',
    '"PRIVATE_KEY" filename:docker-compose.yml',
    '"MNEMONIC" filename:.env.example',
    # General
    '"PRIVATE_KEY" "0x" hex',
    'mnemonic "seed phrase"',
    'filename:wallet.txt "seed"',
    '"private key" "0x" "rpc"',
    '"seed" "mnemonic" "wallet" filetype:env',
    '"secret" "private" "key" filetype:env',
    '"0x" "private" "key" "infura"',
    '"0x" "private" "key" "alchemy"',
    # Solana-specific
    '"PRIVATE_KEY" base58 solana',
    '"phantom" "private" "key" filetype:env',
    '"solana" "private" "key" "rpc"',
    # Hardhat/Foundry deployments
    '"DEPLOYER_PRIVATE_KEY" filetype:env',
    '"PRIVATE_KEY_DEPLOYER" filetype:env',
    # Bot/trading configs
    '"TRADING_BOT" "PRIVATE_KEY" filetype:env',
    '"SNIPER" "PRIVATE_KEY" filetype:env',
    '"flashbot" "private" "key"',
    # Wallet seed exports
    '"seed phrase" "do not share"',
    '"recovery phrase" "private"',
    '"mnemonic phrase" filetype:env',
    # .env.development / .env.local
    'filename:.env.development "PRIVATE_KEY"',
    'filename:.env.local "SECRET"',
    'filename:.env.production "PRIVATE_KEY"',
]

class GitHubLeakSource:
    SEARCH_URL = "https://api.github.com/search/code"
    def __init__(self, github_token: Optional[str] = None, rate_limit: int = 0, timeout: float = 30.0):
        self.github_token = github_token or ""
        self.rate_limit = rate_limit or (30 if self.github_token else 10)
        self.timeout = timeout
        self._request_times: list[float] = []

    async def fetch_raw_leaks(self, queries: Optional[list[str]] = None, max_per_query: int = 30) -> list[RawLeak]:
        # Rotate queries: pick a random subset each run to cover more ground over time
        if queries is None:
            queries = _random.sample(_QUERIES, min(7, len(_QUERIES)))
        leaks: list[RawLeak] = []
        headers = self._make_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # 1. Code search queries
            for query in queries:
                await self._rate_limit()
                try:
                    # Sort by recently updated to catch fresh leaks before competitors
                    resp = await client.get(self.SEARCH_URL, params={"q": query, "per_page": min(max_per_query, 30), "sort": "updated", "order": "desc"}, headers=headers)
                    if resp.status_code == 403:
                        await asyncio.sleep(60)
                        continue
                    resp.raise_for_status()
                    for item in resp.json().get("items", []):
                        html_url = item.get("html_url", "")
                        text = await self._fetch_raw_file(client, html_url, headers)
                        if text:
                            leaks.append(RawLeak(text=text, source_name="github", source_url=html_url))
                except Exception as exc:
                    logger.error("GitHub search error: %s", exc)

            # 2. Gist scanning (not indexed by code search)
            try:
                gist_leaks = await self._fetch_recent_gists(client, headers)
                leaks.extend(gist_leaks)
            except Exception as exc:
                logger.error("GitHub gist scan error: %s", exc)

        return leaks

    async def _fetch_recent_gists(self, client: httpx.AsyncClient, headers: dict[str, str]) -> list[RawLeak]:
        """Fetch recent public gists and scan for keys/mnemonics."""
        leaks: list[RawLeak] = []
        await self._rate_limit()
        resp = await client.get("https://api.github.com/gists/public", params={"per_page": 100}, headers=headers)
        if resp.status_code != 200:
            return leaks
        for gist in resp.json():
            gist_url = gist.get("html_url", "")
            for file_info in gist.get("files", {}).values():
                raw_url = file_info.get("raw_url", "")
                if not raw_url:
                    continue
                await self._rate_limit()
                try:
                    fresp = await client.get(raw_url, headers=headers)
                    if fresp.status_code == 200 and fresp.text.strip():
                        leaks.append(RawLeak(text=fresp.text, source_name="github_gist", source_url=gist_url))
                except Exception:
                    pass
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        return await self.fetch_raw_leaks(queries=[f'"{address}"'])

    def _make_headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            h["Authorization"] = f"token {self.github_token}"
        return h

    async def _fetch_raw_file(self, client: httpx.AsyncClient, html_url: str, headers: dict[str, str]) -> Optional[str]:
        await self._rate_limit()
        try:
            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            resp = await client.get(raw_url, headers=headers)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return None

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= self.rate_limit:
            wait = 60 - (now - self._request_times[0])
            if wait > 0:
                await asyncio.sleep(wait)
        self._request_times.append(time.monotonic())
