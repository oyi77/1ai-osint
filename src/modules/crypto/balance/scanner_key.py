"""Dedicated scanner for leaked private keys on GitHub and paste sites."""

from __future__ import annotations

import asyncio
import logging
import os
import re

import httpx

from src.modules.crypto.balance._leak_shared import (
    LeakFinding,
)
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)


class KeyLeakScanner:
    """Dedicated scanner for leaked private keys on GitHub and paste sites.

    Searches for raw hex, base58, and WIF private keys in public sources,
    derives wallet addresses, and checks balances.
    """

    SEARCH_URL = "https://api.github.com/search/code"
    RATE_LIMIT = 30

    GITHUB_QUERIES = [
        '"PRIVATE_KEY" filetype:env',
        '"private_key" solana OR ethereum',
        '"PRIVATE_KEY=" "0x"',
        '"ed25519" "private" secret',
        '"base58" "private_key"',
        '"WIF" "private_key" bitcoin',
    ]

    PASTE_SOURCES = [
        "https://pastebin.com/archive",
        "https://paste.ee/archive",
    ]

    def __init__(
        self,
        github_token: str | None = None,
        hit_logger: HitLogger | None = None,
    ):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.hit_logger = hit_logger
        self._request_times: list[float] = []

    async def scan_github(self, max_results: int = 100) -> list[LeakFinding]:
        """Search GitHub for leaked private keys.

        Args:
            max_results: Max results per query.

        Returns:
            List of LeakFinding objects with private key candidates.

        """
        findings = []
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async with httpx.AsyncClient(timeout=30) as client:
            for query in self.GITHUB_QUERIES:
                await self._rate_limit()
                try:
                    resp = await client.get(
                        self.SEARCH_URL,
                        params={"q": query, "per_page": min(max_results, 30)},
                        headers=headers,
                    )
                    if resp.status_code == 403:
                        logger.warning("GitHub API rate limited — pausing")
                        await asyncio.sleep(60)
                        continue
                    resp.raise_for_status()
                    data = resp.json()

                    for item in data.get("items", []):
                        file_url = item.get("html_url", "")
                        finding = await self._fetch_and_scan_key(client, file_url, headers)
                        if finding:
                            findings.append(finding)
                except httpx.HTTPStatusError as e:
                    logger.error("GitHub key search error: %s", e)
                except Exception as e:
                    logger.error("GitHub key scan error: %s", e)

        return findings

    async def scan_pastes(self, max_pastes: int = 50) -> list[LeakFinding]:
        """Scan paste sites for leaked private keys.

        Args:
            max_pastes: Max pastes to check per source.

        Returns:
            List of LeakFinding objects with private key candidates.

        """
        findings = []
        async with httpx.AsyncClient(timeout=30) as client:
            for source in self.PASTE_SOURCES:
                try:
                    paste_urls = await self._get_paste_urls(client, source, max_pastes)
                    for url in paste_urls:
                        finding = await self._scan_paste_key(client, url)
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    logger.error("Paste key scan error (%s): %s", source, e)
        return findings

    async def scan(self, max_results: int = 100, max_pastes: int = 50) -> list[LeakFinding]:
        """Run full key leak scan across GitHub and paste sites.

        Returns:
            Combined list of LeakFinding objects from all sources.

        """
        github_findings = await self.scan_github(max_results)
        paste_findings = await self.scan_pastes(max_pastes)
        return github_findings + paste_findings

    async def _fetch_and_scan_key(
        self,
        client: httpx.AsyncClient,
        file_url: str,
        headers: dict,
    ) -> LeakFinding | None:
        """Fetch a GitHub file and scan for private keys."""
        await self._rate_limit()
        try:
            raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            resp = await client.get(raw_url, headers=headers)
            resp.raise_for_status()
            text = resp.text

            from src.modules.crypto.privatekey.scanner import detect_key_format

            keys = detect_key_format(text)
            if keys:
                for k in keys:
                    if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                        return LeakFinding(
                            source="github_key",
                            source_url=file_url,
                            mnemonic_candidate=k["match"],
                            is_valid=False,
                            source_type="private_key",
                        )
        except Exception as e:
            logger.debug("Failed to fetch %s: %s", file_url, e)
        return None

    async def _scan_paste_key(self, client: httpx.AsyncClient, paste_url: str) -> LeakFinding | None:
        """Fetch a paste and scan for private keys."""
        try:
            raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
            resp = await client.get(raw_url)
            resp.raise_for_status()
            text = resp.text

            from src.modules.crypto.privatekey.scanner import detect_key_format

            keys = detect_key_format(text)
            if keys:
                for k in keys:
                    if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                        return LeakFinding(
                            source="pastebin_key",
                            source_url=paste_url,
                            mnemonic_candidate=k["match"],
                            is_valid=False,
                            source_type="private_key",
                        )
        except Exception as e:
            logger.debug("Failed to scan paste %s: %s", paste_url, e)
        return None

    async def _get_paste_urls(self, client: httpx.AsyncClient, archive_url: str, limit: int) -> list[str]:
        """Extract paste URLs from an archive page."""
        try:
            resp = await client.get(archive_url)
            resp.raise_for_status()
            urls = re.findall(r"https?://pastebin\.com/[a-zA-Z0-9]+", resp.text)
            return list(dict.fromkeys(urls))[:limit]
        except Exception:
            return []

    async def _rate_limit(self):
        """Enforce GitHub API rate limit (30 req/min)."""
        import time

        now = time.monotonic()
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= self.RATE_LIMIT:
            wait = 60 - (now - self._request_times[0])
            if wait > 0:
                logger.debug("GitHub rate limit: waiting %.1fs", wait)
                await asyncio.sleep(wait)
        self._request_times.append(time.monotonic())
