"""Wayback Machine source adapter for crypto leak discovery."""

from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "private key",
    "mnemonic seed",
    "wallet backup",
    ".env",
    "keystore.json",
    "config.json private",
]


class WaybackSource:
    """Scan Wayback Machine for archived pages with crypto key leaks."""

    CDX_URL = "https://web.archive.org/cdx/search/cdx"

    def __init__(
        self, max_per_query: int = 20, request_delay: float = 2.0, timeout: float = 30.0
    ):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search Wayback Machine for archived pages with crypto leaks."""
        leaks: list[RawLeak] = []
        seen_urls: set[str] = set()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for query in _QUERIES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        self.CDX_URL,
                        params={
                            "url": f"*.{query.replace(' ', '*')}*",
                            "output": "json",
                            "limit": self.max_per_query,
                            "fl": "original,timestamp,statuscode",
                            "filter": "statuscode:200",
                        },
                    )
                    if resp.status_code != 200:
                        continue
                    rows = resp.json()
                    if not rows or len(rows) < 2:
                        continue
                    for row in rows[1:]:
                        url = row[0]
                        if url in seen_urls:
                            continue
                        seen_urls.add(url)
                        # Fetch the archived page
                        try:
                            await self._rate_limit()
                            page_resp = await client.get(
                                f"https://web.archive.org/web/{row[1]}/{url}",
                                follow_redirects=True,
                            )
                            if page_resp.status_code == 200:
                                text = page_resp.text[:50000]
                                if text.strip():
                                    leaks.append(
                                        RawLeak(
                                            text=text,
                                            source_name="wayback",
                                            source_url=url,
                                        )
                                    )
                        except Exception:
                            pass
                except Exception as exc:
                    logger.debug("Wayback query '%s' error: %s", query, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Wayback Machine for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.CDX_URL,
                    params={
                        "url": f"*{address}*",
                        "output": "json",
                        "limit": 10,
                        "fl": "original,timestamp,statuscode",
                        "filter": "statuscode:200",
                    },
                )
                if resp.status_code == 200:
                    rows = resp.json()
                    if rows and len(rows) >= 2:
                        for row in rows[1:]:
                            try:
                                await self._rate_limit()
                                page_resp = await client.get(
                                    f"https://web.archive.org/web/{row[1]}/{row[0]}",
                                    follow_redirects=True,
                                )
                                if page_resp.status_code == 200:
                                    leaks.append(
                                        RawLeak(
                                            text=page_resp.text[:50000],
                                            source_name="wayback",
                                            source_url=row[0],
                                        )
                                    )
                            except Exception:
                                pass
            except Exception as exc:
                logger.debug("Wayback address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
