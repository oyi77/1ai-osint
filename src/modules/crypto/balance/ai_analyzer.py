"""AI word frequency analyzer for BIP-39 mnemonic corpus analysis.

Analyzes word frequency patterns in known mnemonic phrases and produces
weighted distributions that can bias mnemonic generation toward more
commonly-found words.

The 12th word's last 4 bits are SHA-256 checksum of the first 128 bits
of entropy (BIP-39 spec).
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from typing import Optional

from bip_utils import Bip39Languages, Bip39MnemonicEncoder, Bip39MnemonicValidator

logger = logging.getLogger(__name__)

_DB_PATH = "wallet_hits.db"
_TABLE_NAME = "word_frequencies"


def _get_bip39_wordlist() -> list[str]:
    """Return the BIP-39 English wordlist (2048 words in spec order)."""
    enc = Bip39MnemonicEncoder(Bip39Languages.ENGLISH)
    wl = enc.m_words_list
    return [wl.GetWordAtIdx(i) for i in range(wl.Length())]


class WordFrequencyAnalyzer:
    """Computes and persists word frequency weights from a corpus of mnemonics.

    Each of the 2048 BIP-39 English words gets a float weight in [0, 1].
    Higher weight = more frequent in the observed corpus.  Uniform weights
    when no corpus has been analyzed yet.

    Usage::

        analyzer = WordFrequencyAnalyzer()
        analyzer.analyze_corpus(["word1 ... word12", ...])
        analyzer.save_to_db()
        weighted = analyzer.get_weighted_wordlist()
    """

    def __init__(self, db_path: str = _DB_PATH):
        self._db_path = db_path
        self._wordlist = _get_bip39_wordlist()
        self._word_index: dict[str, int] = {w: i for i, w in enumerate(self._wordlist)}
        # weights[i] = weight for self._wordlist[i], default uniform 1.0
        self._weights: dict[str, float] = {w: 1.0 for w in self._wordlist}
        self._validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)

    # ------------------------------------------------------------------
    # Corpus analysis
    # ------------------------------------------------------------------

    def analyze_corpus(self, mnemonics: list[str]) -> dict[str, float]:
        """Compute word frequency weights from a list of mnemonic phrases.

        Args:
            mnemonics: List of space-separated BIP-39 mnemonic strings.

        Returns:
            Dict mapping each BIP-39 word to its normalized weight in [0, 1].
        """
        counts: dict[str, int] = {w: 0 for w in self._wordlist}
        valid_count = 0

        for mnemonic in mnemonics:
            words = mnemonic.strip().lower().split()
            # Only count words that are in the BIP-39 wordlist
            for word in words:
                if word in counts:
                    counts[word] += 1
            valid_count += 1

        max_count = max(counts.values()) if counts else 1
        if max_count == 0:
            max_count = 1

        # Log-scale normalization: avoids extreme skew from very common words
        import math
        for word, count in counts.items():
            self._weights[word] = math.log(1 + count) / math.log(1 + max_count)

        logger.info(
            "Analyzed %d mnemonics, %d unique BIP-39 words found, max count=%d",
            valid_count, sum(1 for c in counts.values() if c > 0), max_count,
        )
        return dict(self._weights)

    # ------------------------------------------------------------------
    # SQLite persistence
    # ------------------------------------------------------------------

    def save_to_db(self, db_path: Optional[str] = None) -> None:
        """Persist current weights to the ``word_frequencies`` SQLite table."""
        path = db_path or self._db_path
        conn = sqlite3.connect(path)
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {_TABLE_NAME} (
                word TEXT PRIMARY KEY,
                weight REAL NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.executemany(
            f"INSERT OR REPLACE INTO {_TABLE_NAME} (word, weight) VALUES (?, ?)",
            [(w, wt) for w, wt in self._weights.items()],
        )
        conn.commit()
        conn.close()
        logger.info("Saved %d word weights to %s:%s", len(self._weights), path, _TABLE_NAME)

    def load_from_db(self, db_path: Optional[str] = None) -> bool:
        """Load weights from the ``word_frequencies`` SQLite table.

        Returns:
            True if weights were loaded, False if table was missing or empty.
        """
        path = db_path or self._db_path
        try:
            conn = sqlite3.connect(path)
            rows = conn.execute(
                f"SELECT word, weight FROM {_TABLE_NAME}"
            ).fetchall()
            conn.close()

            if not rows:
                logger.debug("No word weights found in %s:%s", path, _TABLE_NAME)
                return False

            for word, weight in rows:
                if word in self._weights:
                    self._weights[word] = weight

            logger.info("Loaded %d word weights from %s:%s", len(rows), path, _TABLE_NAME)
            return True
        except sqlite3.OperationalError:
            logger.debug("Table %s not found in %s", _TABLE_NAME, path)
            return False

    # ------------------------------------------------------------------
    # Weighted wordlist
    # ------------------------------------------------------------------

    def get_weighted_wordlist(self) -> list[tuple[str, float]]:
        """Return (word, weight) pairs for all 2048 BIP-39 words.

        Returns:
            List of (word, weight) tuples sorted by word (same order as BIP-39 spec).
        """
        return [(w, self._weights[w]) for w in self._wordlist]

    # ------------------------------------------------------------------
    # Validation: biased generation compliance
    # ------------------------------------------------------------------

    def validate_biased_generation(self, n: int = 1000) -> float:
        """Simulate biased mnemonic generation and measure BIP-39 compliance.

        Generates ``n`` mnemonics by sampling from the current weight
        distribution, then checks how many pass BIP-39 checksum validation.

        Args:
            n: Number of mnemonics to simulate.

        Returns:
            Fraction in [0, 1] of generated mnemonics that are BIP-39 valid.
        """
        import random

        valid = 0
        weights = [self._weights[w] for w in self._wordlist]

        for _ in range(n):
            # Sample 11 words from weighted distribution
            first_11 = random.choices(self._wordlist, weights=weights, k=11)

            # Try candidate 12th words until checksum is valid
            entropy_bits = 0
            for word in first_11:
                idx = self._word_index[word]
                entropy_bits = (entropy_bits << 11) | idx
            # entropy_bits now has 121 bits (11 words * 11 bits)

            mnemonic = None
            for candidate in random.sample(self._wordlist, min(256, len(self._wordlist))):
                cand_idx = self._word_index[candidate]
                # Full 132-bit value: 121 bits from first 11 + 11 bits from 12th
                full_value = (entropy_bits << 11) | cand_idx
                # Extract 128-bit entropy (first 128 bits) and 4-bit checksum (last 4 bits)
                entropy_128 = full_value >> 4
                checksum_bits = full_value & 0x0F

                # Compute expected checksum: first 4 bits of SHA-256(entropy)
                entropy_bytes = entropy_128.to_bytes(16, byteorder="big")
                sha = hashlib.sha256(entropy_bytes).digest()
                expected_checksum = (sha[0] >> 4) & 0x0F

                if checksum_bits == expected_checksum:
                    mnemonic = " ".join(first_11 + [candidate])
                    break

            if mnemonic and self._validator.IsValid(mnemonic):
                valid += 1

        rate = valid / n if n > 0 else 0.0
        logger.info("Biased generation validation: %d/%d valid (%.2f%%)", valid, n, rate * 100)
        return rate
