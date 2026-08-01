"""Etherscan source adapter for blockchain wallet analysis."""

from __future__ import annotations

import asyncio
import logging
import os
import time

import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class EtherscanSource:
    """Query Etherscan API for wallet transaction history and balances."""

    BASE_URL = "https://api.etherscan.io/api"

    def __init__(
        self,
        api_key: str | None = None,
        request_delay: float = 0.25,
        timeout: float = 15.0,
    ):
        self.api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Etherscan requires an address target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search Etherscan for wallet transactions and token transfers.

        Works without an API key (rate-limited public endpoint); the key is
        attached only when configured.
        """
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # Get normal transactions
            try:
                await self._rate_limit()
                params: dict[str, str | int] = {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": 10,
                    "sort": "desc",
                }
                if self.api_key:
                    params["apikey"] = self.api_key
                resp = await client.get(self.BASE_URL, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "1":
                        for tx in data.get("result", []):
                            leaks.append(
                                RawLeak(
                                    text=f"Tx: {tx.get('hash', '')}\nFrom: {tx.get('from', '')}\nTo: {tx.get('to', '')}\nValue: {tx.get('value', '')}",
                                    source_name="etherscan",
                                    source_url=f"https://etherscan.io/tx/{tx.get('hash', '')}",
                                )
                            )
            except Exception as exc:
                logger.debug("Etherscan txlist error: %s", exc)

            # Get ERC-20 token transfers
            try:
                await self._rate_limit()
                params = {
                    "module": "account",
                    "action": "tokentx",
                    "address": address,
                    "page": 1,
                    "offset": 10,
                    "sort": "desc",
                }
                if self.api_key:
                    params["apikey"] = self.api_key
                resp = await client.get(self.BASE_URL, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "1":
                        for tx in data.get("result", []):
                            leaks.append(
                                RawLeak(
                                    text=f"Token: {tx.get('tokenName', '')} ({tx.get('tokenSymbol', '')})\nFrom: {tx.get('from', '')}\nTo: {tx.get('to', '')}\nValue: {tx.get('value', '')}",
                                    source_name="etherscan_token",
                                    source_url=f"https://etherscan.io/tx/{tx.get('hash', '')}",
                                )
                            )
            except Exception as exc:
                logger.debug("Etherscan tokentx error: %s", exc)

        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
