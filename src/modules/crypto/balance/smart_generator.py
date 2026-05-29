"""Smart mnemonic generator biased by word frequency analysis.

Generates BIP-39 valid 12-word mnemonics where words 1-11 are sampled
from a weighted distribution (via WordFrequencyAnalyzer) and the 12th
word is iterated until the BIP-39 checksum constraint is satisfied.

BIP-39 checksum for 12 words: 128 bits entropy + 4 bits SHA-256 checksum.
The 12th word encodes 7 entropy bits + 4 checksum bits.
"""

from __future__ import annotations

import hashlib
import logging
import random

from bip_utils import Bip39Languages, Bip39MnemonicValidator

from src.modules.crypto.balance.ai_analyzer import WordFrequencyAnalyzer

logger = logging.getLogger(__name__)


class SmartMnemonicGenerator:
    """Generate BIP-39 valid mnemonics biased by observed word frequencies.

    Uses a WordFrequencyAnalyzer to weight word selection toward
    commonly-observed patterns while maintaining strict BIP-39 compliance.

    Usage::

        analyzer = WordFrequencyAnalyzer()
        analyzer.load_from_db()
        gen = SmartMnemonicGenerator(analyzer)
        mnemonic = gen.generate()
        batch = gen.generate_batch(100)
    """

    def __init__(self, analyzer: WordFrequencyAnalyzer):
        self._analyzer = analyzer
        self._validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
        self._wordlist = [w for w, _ in analyzer.get_weighted_wordlist()]
        self._weights = [wt for _, wt in analyzer.get_weighted_wordlist()]
        self._word_index: dict[str, int] = {w: i for i, w in enumerate(self._wordlist)}

    def generate(self) -> str:
        """Generate a single valid BIP-39 12-word mnemonic.

        Algorithm:
        1. Sample words 1-11 from weighted distribution.
        2. Compute 121-bit prefix from word indices.
        3. Iterate candidate 12th words until SHA-256 checksum matches.

        Returns:
            A space-separated 12-word BIP-39 mnemonic string.

        Raises:
            RuntimeError: If no valid 12th word found after exhausting candidates.
        """
        # Step 1: Sample first 11 words from weighted distribution
        first_11 = random.choices(self._wordlist, weights=self._weights, k=11)

        # Step 2: Build 121-bit prefix (11 words * 11 bits each)
        entropy_prefix = 0
        for word in first_11:
            entropy_prefix = (entropy_prefix << 11) | self._word_index[word]

        # Step 3: Try candidate 12th words until checksum is valid
        # Shuffle candidates to avoid deterministic bias but try weighted ones first
        candidates = list(range(2048))
        random.shuffle(candidates)

        for cand_idx in candidates:
            # Full 132-bit value: 121 bits prefix + 11 bits for 12th word
            full_value = (entropy_prefix << 11) | cand_idx
            # Extract 128-bit entropy (top 128 bits) and 4-bit checksum (bottom 4 bits)
            entropy_128 = full_value >> 4
            checksum_bits = full_value & 0x0F

            # Compute expected checksum: first 4 bits of SHA-256(entropy)
            entropy_bytes = entropy_128.to_bytes(16, byteorder="big")
            sha = hashlib.sha256(entropy_bytes).digest()
            expected_checksum = (sha[0] >> 4) & 0x0F

            if checksum_bits == expected_checksum:
                mnemonic = " ".join(first_11 + [self._wordlist[cand_idx]])
                # Final validation via bip_utils as a safety net
                if self._validator.IsValid(mnemonic):
                    return mnemonic

        # Statistically unreachable (~1 in 16 chance per candidate, 2048 candidates)
        raise RuntimeError("Failed to generate valid BIP-39 mnemonic (exhausted 2048 candidates)")

    def generate_batch(self, count: int) -> list[str]:
        """Generate multiple valid BIP-39 mnemonics.

        Args:
            count: Number of mnemonics to generate.

        Returns:
            List of space-separated 12-word mnemonic strings.
        """
        mnemonics: list[str] = []
        for _ in range(count):
            mnemonics.append(self.generate())
        return mnemonics
