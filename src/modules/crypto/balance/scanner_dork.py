"""Google/Bing dork scanner for mnemonic leaks in public files."""

from __future__ import annotations

import logging
import os
import re
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


class DorkScanner:
    """Google/Bing dork scanner for mnemonic leaks in files.

    Uses search engine dork queries to find leaked mnemonic phrases
    and private keys in publicly indexed files (.env, wallet.txt, seed.txt).
    """

    DORK_QUERIES = [
        # Mnemonic / seed phrase dorks
        '"my mnemonic" "word1 word2" filetype:txt',
        '"seed phrase" wallet filetype:txt',
        '"bip39" "mnemonic" filetype:env',
        '"12 word" "seed" wallet filetype:txt',
        '"24 word" "mnemonic" filetype:log',
        # Private key dorks
        '"PRIVATE_KEY" filetype:env',
        '"private_key" solana OR ethereum filetype:env',
        '"PRIVATE_KEY=" "0x"',
    ]

    # Bing search endpoint
    BING_URL = "https://www.bing.com/search"

    def __init__(
        self,
        hit_logger: Optional[HitLogger] = None,
        github_token: Optional[str] = None,
    ):
        self.hit_logger = hit_logger
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")

    async def scan(self, max_results: int = 50) -> list[LeakFinding]:
        """Run dork queries and scan results for mnemonic leaks.

        Args:
            max_results: Max results to process per query.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []

        async with httpx.AsyncClient(timeout=30) as client:
            for query in self.DORK_QUERIES:
                try:
                    urls = await self._search_bing(client, query, max_results)
                    for url in urls:
                        finding = await self._fetch_and_scan(client, url)
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    logger.error("Dork scan error for '%s': %s", query, e)

        return findings

    async def _search_bing(
        self, client: httpx.AsyncClient, query: str, limit: int
    ) -> list[str]:
        """Search Bing and return result URLs."""
        try:
            resp = await client.get(
                self.BING_URL,
                params={"q": query, "count": min(limit, 50)},
                headers={"User-Agent": "Mozilla/5.0"},
            )
            resp.raise_for_status()
            # Extract URLs from search results
            urls = re.findall(
                r'<a[^>]+href="(https?://[^"]+)"',
                resp.text,
            )
            # Filter out Bing's own URLs
            urls = [
                u for u in urls
                if not any(domain in u for domain in ["bing.com", "microsoft.com", "go.microsoft"])
            ]
            return urls[:limit]
        except Exception as e:
            logger.debug("Bing search error for '%s': %s", query, e)
            return []

    async def _fetch_and_scan(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[LeakFinding]:
        """Fetch a URL and scan for mnemonic patterns."""
        try:
            # Skip binary files
            if any(url.endswith(ext) for ext in (".png", ".jpg", ".gif", ".zip", ".pdf")):
                return None

            resp = await client.get(url, follow_redirects=True)
            resp.raise_for_status()
            text = resp.text

            # Pass 1: mnemonic detection
            candidates = MnemonicPatternDetector.find_mnemonics(text)
            if candidates:
                return LeakFinding(
                    source="dork",
                    source_url=url,
                    mnemonic_candidate=candidates[0],
                    is_valid=True,
                )

            # Pass 2: private key detection
            from src.modules.crypto.privatekey.scanner import detect_key_format
            keys = detect_key_format(text)
            if keys:
                for k in keys:
                    if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                        return LeakFinding(
                            source="dork",
                            source_url=url,
                            mnemonic_candidate=k["match"],
                            is_valid=False,
                            source_type="private_key",
                        )
        except Exception as e:
            logger.debug("Failed to fetch %s: %s", url, e)

        return None

    async def verify_and_alert(
        self,
        mnemonic_candidate: str,
        chains: Optional[list[ChainConfig]] = None,
        count: int = 6,
    ) -> Optional[LeakFinding]:
        """Validate and check a dork-sourced mnemonic candidate.

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
            source="dork",
        )