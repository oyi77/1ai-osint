"""GitHub code search scanner for BIP-39 mnemonic and private key patterns."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import httpx

from src.modules.crypto.balance._leak_shared import (
    LeakFinding,
    MnemonicPatternDetector,
    verify_and_alert,
)
from src.modules.crypto.balance.chains import ChainConfig
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)


class GitHubLeakScanner:
    """GitHub code search for BIP-39 mnemonic patterns.

    Uses GitHub's code search API to find leaked mnemonic phrases
    and private keys in public repositories.
    """

    SEARCH_URL = "https://api.github.com/search/code"
    RATE_LIMIT = 30

    def __init__(
        self,
        github_token: Optional[str] = None,
        hit_logger: Optional[HitLogger] = None,
    ):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.hit_logger = hit_logger
        self._request_times: list[float] = []

    async def scan(self, max_results: int = 100) -> list[LeakFinding]:
        """Search GitHub for leaked mnemonics and private keys.

        Args:
            max_results: Max results per query.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []
        queries = [
            "mnemonic 12 words",
            "seed phrase wallet backup",
            "bip39 mnemonic",
            # Private key searches
            '"PRIVATE_KEY" filetype:env',
            '"private_key" solana OR ethereum',
            '"PRIVATE_KEY=" "0x"',
            '"ed25519" "private" secret',
        ]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async with httpx.AsyncClient(timeout=30) as client:
            for query in queries:
                # Rate limiting: max 30 req/min
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
                        # Fetch file content
                        finding = await self._fetch_and_scan(client, file_url, headers)
                        if finding:
                            findings.append(finding)

                except httpx.HTTPStatusError as e:
                    logger.error("GitHub search error: %s", e)
                except Exception as e:
                    logger.error("GitHub scan error: %s", e)

        return findings

    async def _fetch_and_scan(
        self,
        client: httpx.AsyncClient,
        file_url: str,
        headers: dict,
    ) -> Optional[LeakFinding]:
        """Fetch a GitHub file and scan for mnemonics and private keys."""
        await self._rate_limit()

        try:
            # Convert HTML URL to raw content URL
            raw_url = file_url.replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")
            resp = await client.get(raw_url, headers=headers)
            resp.raise_for_status()
            text = resp.text

            # Pass 1: mnemonic detection
            candidates = MnemonicPatternDetector.find_mnemonics(text)
            if candidates:
                return LeakFinding(
                    source="github",
                    source_url=file_url,
                    mnemonic_candidate=candidates[0],
                    is_valid=True,
                )

            # Pass 2: private key detection (hex, base58, WIF)
            from src.modules.crypto.privatekey.scanner import detect_key_format

            keys = detect_key_format(text)
            if keys:
                # Return the first high-confidence key found
                for k in keys:
                    if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                        return LeakFinding(
                            source="github",
                            source_url=file_url,
                            mnemonic_candidate=k["match"],
                            is_valid=False,
                            source_type="private_key",
                        )
        except Exception as e:
            logger.debug("Failed to fetch %s: %s", file_url, e)

        return None

    async def _rate_limit(self):
        """Enforce GitHub API rate limit (30 req/min)."""
        import time

        now = time.monotonic()
        # Remove requests older than 60 seconds
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= self.RATE_LIMIT:
            # Wait until the oldest request is > 60s old
            wait = 60 - (now - self._request_times[0])
            if wait > 0:
                logger.debug("GitHub rate limit: waiting %.1fs", wait)
                await asyncio.sleep(wait)
        self._request_times.append(time.monotonic())

    async def verify_and_alert(
        self,
        mnemonic_candidate: str,
        chains: Optional[list[ChainConfig]] = None,
        count: int = 6,
    ) -> Optional[LeakFinding]:
        """Validate and check a GitHub-sourced mnemonic candidate.

        Delegates to the standalone verify_and_alert function.

        Args:
            mnemonic_candidate: Potential mnemonic phrase to verify.
            chains: Chains to check. Defaults to all.
            count: Number of address indices to derive per chain (default 6 for leak-sourced).
        """
        return await verify_and_alert(
            mnemonic_candidate,
            chains=chains,
            hit_logger=self.hit_logger,
            count=count,
            source="github",
        )
