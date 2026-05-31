"""StackOverflow source adapter for crypto leak discovery."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_QUERIES = [
    "private key hex 0x",
    "mnemonic seed phrase wallet",
    "web3 private key hardcoded",
    "ethers wallet privateKey",
    "solana keypair base58",
    "private key env file",
    "crypto wallet import key",
    "hardhat deployer private key",
    "truffle private key config",
    "metamask export private key",
    "phantom wallet private key",
    "trust wallet recovery phrase",
]

class StackOverflowSource:
    """Scan StackOverflow for leaked crypto keys in code snippets."""

    API_URL = "https://api.stackexchange.com/2.3/search/advanced"

    def __init__(self, max_per_query: int = 30, request_delay: float = 2.0, timeout: float = 30.0):
        self.max_per_query = max_per_query
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Search StackOverflow for questions/answers with crypto key leaks."""
        leaks: list[RawLeak] = []
        seen_ids: set[int] = set()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for query in _QUERIES:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        self.API_URL,
                        params={
                            "q": query,
                            "site": "stackoverflow",
                            "filter": "withbody",
                            "pagesize": min(self.max_per_query, 100),
                            "sort": "relevance",
                        },
                    )
                    if resp.status_code != 200:
                        logger.debug("StackOverflow query '%s' returned %d", query, resp.status_code)
                        continue
                    data = resp.json()
                    for item in data.get("items", []):
                        item_id = item.get("question_id", 0)
                        if item_id in seen_ids:
                            continue
                        seen_ids.add(item_id)
                        body = item.get("body", "")
                        title = item.get("title", "")
                        combined = f"{title}\n{body}"
                        if combined.strip():
                            link = item.get("link", f"https://stackoverflow.com/questions/{item_id}")
                            leaks.append(RawLeak(
                                text=combined,
                                source_name="stackoverflow",
                                source_url=link,
                            ))
                except Exception as exc:
                    logger.error("StackOverflow query '%s' error: %s", query, exc)

            # Also search answers with code blocks containing keys
            answer_queries = [
                "private_key 0x",
                "mnemonic phrase words",
                "secret_key base58",
            ]
            for query in answer_queries:
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        "https://api.stackexchange.com/2.3/search/advanced",
                        params={
                            "q": query,
                            "site": "stackoverflow",
                            "filter": "withbody",
                            "pagesize": 30,
                            "sort": "votes",
                            "accepted": "True",
                        },
                    )
                    if resp.status_code != 200:
                        continue
                    for item in resp.json().get("items", []):
                        item_id = item.get("question_id", 0)
                        if item_id in seen_ids:
                            continue
                        seen_ids.add(item_id)
                        body = item.get("body", "")
                        title = item.get("title", "")
                        combined = f"{title}\n{body}"
                        if combined.strip():
                            link = item.get("link", f"https://stackoverflow.com/questions/{item_id}")
                            leaks.append(RawLeak(
                                text=combined,
                                source_name="stackoverflow",
                                source_url=link,
                            ))
                except Exception as exc:
                    logger.error("StackOverflow answer query '%s' error: %s", query, exc)

        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search StackOverflow for a specific address."""
        leaks: list[RawLeak] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                await self._rate_limit()
                resp = await client.get(
                    self.API_URL,
                    params={
                        "q": f'"{address}"',
                        "site": "stackoverflow",
                        "filter": "withbody",
                        "pagesize": 30,
                    },
                )
                if resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        body = item.get("body", "")
                        title = item.get("title", "")
                        combined = f"{title}\n{body}"
                        if combined.strip():
                            link = item.get("link", "")
                            leaks.append(RawLeak(
                                text=combined,
                                source_name="stackoverflow",
                                source_url=link,
                            ))
            except Exception as exc:
                logger.error("StackOverflow address search error: %s", exc)
        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
