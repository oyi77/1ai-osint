"""VirusTotal source adapter for crypto leak discovery."""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class VirusTotalSource:
    """Scan VirusTotal for URL/domain analysis related to crypto leaks."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        request_delay: float = 15.0,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search VirusTotal for crypto-related URLs."""
        if not self.api_key:
            logger.debug("VirusTotal: no API key configured, skipping")
            return []

        leaks: list[RawLeak] = []
        queries = [
            "crypto wallet private key",
            "mnemonic seed phrase leak",
            "bitcoin private key",
        ]
        headers = {"x-apikey": self.api_key}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for query in queries:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"{self.BASE_URL}/search",
                        params={"query": query},
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", [])
                        for item in data:
                            attrs = item.get("attributes", {})
                            url = attrs.get("url", "")
                            if url:
                                leaks.append(
                                    RawLeak(
                                        text=f"URL: {url}\nTags: {attrs.get('tags', [])}",
                                        source_name="virustotal",
                                        source_url=url,
                                    )
                                )
                except Exception as exc:
                    logger.debug("VirusTotal query '%s' error: %s", query, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search VirusTotal for a specific address/domain."""
        if not self.api_key:
            return []

        leaks: list[RawLeak] = []
        headers = {"x-apikey": self.api_key}
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    f"{self.BASE_URL}/domains/{address}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attrs = data.get("attributes", {})
                    leaks.append(
                        RawLeak(
                            text=f"Domain: {address}\nReputation: {attrs.get('reputation', 'unknown')}\nTags: {attrs.get('tags', [])}",
                            source_name="virustotal",
                            source_url=f"https://www.virustotal.com/gui/domain/{address}",
                        )
                    )
            except Exception as exc:
                logger.debug("VirusTotal search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
