"""GitLab source adapter for crypto leak discovery.

Uses GitLab's free public search API (no auth needed).
Searches public repos and snippets for leaked private keys and mnemonics.
"""
from __future__ import annotations
import asyncio
import logging
import time
import httpx
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "PRIVATE_KEY",
    "PRIVATE_KEY=0x",
    "MNEMONIC=",
    "seed phrase",
    "wallet private key",
    "SECRET_KEY=",
    "private_key hex",
    "bip39 mnemonic",
]


class GitLabSource:
    """Scan GitLab public repos for leaked crypto keys/mnemonics."""

    SEARCH_URL = "https://gitlab.com/api/v4/search"
    SNIPPETS_URL = "https://gitlab.com/api/v4/snippets/public"

    def __init__(self, max_per_query: int = 20, request_delay: float = 2.0, timeout: float = 30.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        leaks: list[RawLeak] = []
        headers = {"User-Agent": "osint:crypto-leak-scanner:v1.0"}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # 1. Search code in public projects
            for query in _QUERIES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.SEARCH_URL}/blobs",
                        params={"search": query, "scope": "blobs", "per_page": self.max_per_query},
                        headers=headers,
                    )
                    if resp.status_code != 200:
                        logger.debug("GitLab search '%s' returned %d", query, resp.status_code)
                        continue
                    for item in resp.json():
                        project_id = item.get("project_id", "")
                        data = item.get("data", "")
                        if data:
                            url = f"https://gitlab.com/-/snippets/{project_id}" if project_id else ""
                            leaks.append(RawLeak(text=data, source_name="gitlab", source_url=url))
                except Exception as exc:
                    logger.error("GitLab search error: %s", exc)

            # 2. Search public snippets
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.SNIPPETS_URL,
                    params={"per_page": 20},
                    headers=headers,
                )
                if resp.status_code == 200:
                    for snippet in resp.json():
                        snippet_id = snippet.get("id", "")
                        try:
                            await self._rate_limit()
                            raw_resp = await client.get(
                                f"https://gitlab.com/api/v4/snippets/{snippet_id}/raw",
                                headers=headers,
                            )
                            if raw_resp.status_code == 200 and raw_resp.text.strip():
                                url = f"https://gitlab.com/-/snippets/{snippet_id}"
                                leaks.append(RawLeak(text=raw_resp.text, source_name="gitlab_snippet", source_url=url))
                        except Exception:
                            pass
            except Exception as exc:
                logger.error("GitLab snippets error: %s", exc)

        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
