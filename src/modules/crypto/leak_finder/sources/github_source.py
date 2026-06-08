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

_QUERIES = ['"PRIVATE_KEY" "0x" hex', '"PRIVATE_KEY=" filetype:env', '"SECRET_KEY=" filetype:env', 'filename:wallet.txt "seed"', 'mnemonic "seed phrase"']

class GitHubLeakSource:
    SEARCH_URL = "https://api.github.com/search/code"
    def __init__(self, github_token: Optional[str] = None, rate_limit: int = 0, timeout: float = 30.0):
        self.github_token = github_token or ""
        self.rate_limit = rate_limit or (30 if self.github_token else 10)
        self.timeout = timeout
        self._request_times: list[float] = []

    async def fetch_raw_leaks(self, queries: Optional[list[str]] = None, max_per_query: int = 30) -> list[RawLeak]:
        queries = queries or _QUERIES
        leaks: list[RawLeak] = []
        headers = self._make_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for query in queries:
                await self._rate_limit()
                try:
                    resp = await client.get(self.SEARCH_URL, params={"q": query, "per_page": min(max_per_query, 30)}, headers=headers)
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
