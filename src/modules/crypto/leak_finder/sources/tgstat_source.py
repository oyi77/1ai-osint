"""TGStat source adapter for crypto leak discovery."""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Optional

import httpx

from src.modules.crypto.leak_finder.sources.github_source import RawLeak

logger = logging.getLogger(__name__)

class TGStatSource:
    BASE_URL = "https://api.tgstat.ru"
    def __init__(self, api_token: Optional[str] = None, timeout: float = 30.0):
        self.api_token = api_token or os.getenv("TGSTAT_API_TOKEN", "")
        self.timeout = timeout
        self._requests_today: int = 0

    async def fetch_raw_leaks(self, queries: Optional[list[str]] = None, max_channels: int = 10) -> list[RawLeak]:
        if not self.api_token:
            return []
        queries = queries or ["crypto leak", "wallet dump", "seed phrase", "private key dump", "mnemonic leak"]
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            channel_ids: list[int] = []
            for query in queries:
                if len(channel_ids) >= max_channels or self._requests_today >= 100:
                    break
                try:
                    data = await self._api_request(client, "/channels/search", {"q": query, "limit": 10})
                    for ch in (data.get("items", []) if data else []):
                        if len(channel_ids) >= max_channels:
                            break
                        ch_id = ch.get("id")
                        if ch_id and ch_id not in channel_ids:
                            channel_ids.append(ch_id)
                except Exception as exc:
                    logger.error("TGStat search error: %s", exc)
                await asyncio.sleep(1)
            for ch_id in channel_ids:
                if self._requests_today >= 100:
                    break
                try:
                    data = await self._api_request(client, "/channel/messages", {"channel_id": ch_id, "limit": 50})
                    for msg in (data.get("items", []) if data else []):
                        text = msg.get("text", "")
                        if text:
                            leaks.append(RawLeak(text=text, source_name="tgstat", source_url=""))
                except Exception as exc:
                    logger.error("TGStat message error: %s", exc)
                await asyncio.sleep(1)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        if not self.api_token:
            return []
        leaks: list[RawLeak] = []
        pattern = re.compile(re.escape(address), re.IGNORECASE)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            data = await self._api_request(client, "/messages/search", {"q": address, "limit": 50})
            for msg in (data.get("items", []) if data else []):
                text = msg.get("text", "")
                if text and pattern.search(text):
                    leaks.append(RawLeak(text=text, source_name="tgstat", source_url=""))
        return leaks

    async def _api_request(self, client: httpx.AsyncClient, endpoint: str, params: Optional[dict] = None) -> Optional[dict]:
        params = params or {}
        params["token"] = self.api_token
        resp = await client.get(f"{self.BASE_URL}{endpoint}", params=params)
        self._requests_today += 1
        if resp.status_code == 429:
            return None
        resp.raise_for_status()
        data = resp.json()
        return data.get("response") if data.get("status") == "ok" else None
