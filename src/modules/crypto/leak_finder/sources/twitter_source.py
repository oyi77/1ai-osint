"""Twitter/X source adapter using twitter-cli for crypto leak discovery.

Requires: uv tool install twitter-cli (or pipx install twitter-cli)
Auth: Set TWITTER_AUTH_TOKEN + TWITTER_CT0 env vars, or use browser cookie extraction.
"""
from __future__ import annotations
import asyncio
import json
import logging
import shutil
from typing import Optional
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

logger = logging.getLogger(__name__)

_SEARCH_QUERIES = [
    "seed phrase leak",
    "private key wallet",
    "mnemonic phrase leak",
    "crypto wallet leaked",
    "private key 0x",
    "seed phrase found",
    "wallet dump",
    "mnemonic leaked",
]


class TwitterSource:
    """Scan Twitter/X for leaked crypto keys using twitter-cli."""

    def __init__(self, max_per_query: int = 20, timeout: float = 60.0):
        self.max_per_query = max_per_query
        self.timeout = timeout
        self._cli_path: Optional[str] = shutil.which("twitter")

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        if not self._cli_path:
            logger.debug("twitter-cli not found; skipping Twitter scan")
            return []

        leaks: list[RawLeak] = []
        for query in _SEARCH_QUERIES:
            try:
                results = await self._search(query)
                for tweet in results:
                    text = tweet.get("text", "")
                    tweet_id = tweet.get("id", "")
                    username = tweet.get("author", {}).get("screen_name", "")
                    url = f"https://x.com/{username}/status/{tweet_id}" if username and tweet_id else ""
                    if text:
                        leaks.append(RawLeak(text=text, source_name="twitter", source_url=url))
            except Exception as exc:
                logger.error("Twitter search error for '%s': %s", query, exc)

        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        if not self._cli_path:
            return []
        try:
            results = await self._search(address)
            return [
                RawLeak(
                    text=t.get("text", ""),
                    source_name="twitter",
                    source_url=f"https://x.com/{t.get('author', {}).get('screen_name', '')}/status/{t.get('id', '')}",
                )
                for t in results if t.get("text")
            ]
        except Exception:
            return []

    async def _search(self, query: str) -> list[dict]:
        """Run twitter search and return parsed tweet objects."""
        cmd = [
            self._cli_path, "search", query,
            "--json", "--max", str(self.max_per_query),
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

        if proc.returncode != 0:
            err_msg = stderr.decode().strip()
            if err_msg:
                logger.debug("twitter-cli error: %s", err_msg)
            return []

        try:
            data = json.loads(stdout.decode())
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "tweets" in data:
                return data["tweets"]
            return []
        except json.JSONDecodeError:
            # Try line-delimited JSON
            tweets = []
            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        tweets.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return tweets
