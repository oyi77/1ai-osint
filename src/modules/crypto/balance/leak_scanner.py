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

This module re-exports everything from the split sub-modules for backward
compatibility. New code should import from the specific scanner modules.
"""

from __future__ import annotations

# Shared utilities, dataclasses, and standalone functions
from src.modules.crypto.balance._leak_shared import (
    LeakFinding,
    MnemonicPatternDetector,
    _BIP39_WORDS,
    _SEEN_MNEMONICS,
    _SEEN_MNEMONICS_FILE,
    _find_chain,
    _is_mnemonic_seen,
    _load_bip39_words,
    _load_seen_mnemonics,
    _mark_mnemonic_seen,
    _save_seen_mnemonics,
    verify_and_alert,
    verify_and_alert_key,
)

# Scanner classes
from src.modules.crypto.balance.scanner_dork import DorkScanner
from src.modules.crypto.balance.scanner_github import GitHubLeakScanner
from src.modules.crypto.balance.scanner_paste import PasteSiteScanner
from src.modules.crypto.balance.scanner_key import KeyLeakScanner
from src.modules.crypto.balance.scanner_telegram import TelegramLeakScanner

__all__ = [
    # Data classes & detectors
    "LeakFinding",
    "MnemonicPatternDetector",
    # Standalone verify functions
    "verify_and_alert",
    "verify_and_alert_key",
    # Scanner classes
    "DorkScanner",
    "GitHubLeakScanner",
    "PasteSiteScanner",
    "KeyLeakScanner",
    "TelegramLeakScanner",
    # Internal helpers (exported for backward compatibility)
    "_find_chain",
    "_is_mnemonic_seen",
    "_mark_mnemonic_seen",
    "_load_bip39_words",
    "_load_seen_mnemonics",
    "_save_seen_mnemonics",
    "_BIP39_WORDS",
    "_SEEN_MNEMONICS",
    "_SEEN_MNEMONICS_FILE",
]