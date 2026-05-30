"""Passphrase strength checker: entropy analysis, dictionary collision, scoring.

Provides Shannon entropy calculation, common-word dictionary checks,
and a 0-100 strength score for mnemonic passphrases.
"""

import math
from collections import Counter
from pathlib import Path
from typing import Optional


from src.modules.crypto.passphrase.generator import validate_mnemonic

# Default path to the BIP-39 English wordlist bundled with bip-utils.
# Falls back to a minimal built-in set if file not found.
_BIP39_WORDLIST_PATH: Optional[Path] = None

# Minimal fallback common weak passwords / phrases for dictionary check.
_COMMON_WORDS: set[str] = {
    "password", "123456", "qwerty", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "login", "abc123", "iloveyou",
    "shadow", "sunshine", "trustno1", "batman", "access", "hello",
    "charlie", "donald", "1234", "12345", "123456789", "football",
    "baseball", "soccer", "princess", "solo", "passw0rd", "starwars",
}


class PassphraseStrength:
    """Strength analysis result for a passphrase."""

    def __init__(
        self,
        passphrase: str,
        shannon_entropy: float,
        charset_entropy: float,
        has_dictionary_words: bool,
        dictionary_matches: list[str],
        is_bip39_valid: bool,
        score: int,
        rating: str,
        word_count: int,
    ):
        self.passphrase = passphrase
        self.shannon_entropy = shannon_entropy
        self.charset_entropy = charset_entropy
        self.has_dictionary_words = has_dictionary_words
        self.dictionary_matches = dictionary_matches
        self.is_bip39_valid = is_bip39_valid
        self.score = score
        self.rating = rating
        self.word_count = word_count

    def to_dict(self) -> dict:
        return {
            "shannon_entropy_bits": round(self.shannon_entropy, 2),
            "charset_entropy_bits": round(self.charset_entropy, 2),
            "has_dictionary_words": self.has_dictionary_words,
            "dictionary_matches": self.dictionary_matches,
            "is_bip39_valid": self.is_bip39_valid,
            "score": self.score,
            "rating": self.rating,
            "word_count": self.word_count,
        }

    def __repr__(self) -> str:
        return (
            f"<PassphraseStrength(score={self.score}, rating='{self.rating}', "
            f"entropy={self.shannon_entropy:.1f} bits)>"
        )


def shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string in bits per character.

    Args:
        text: Input string.

    Returns:
        Shannon entropy in bits.
    """
    if not text:
        return 0.0

    freq = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def charset_entropy(text: str) -> float:
    """
    Estimate entropy based on the size of the character set used.

    Returns:
        Entropy in bits (log2(charset_size) * length).
    """
    if not text:
        return 0.0

    charset_size = 0
    if any(c.islower() for c in text):
        charset_size += 26
    if any(c.isupper() for c in text):
        charset_size += 26
    if any(c.isdigit() for c in text):
        charset_size += 10
    special = set(text) - set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
    charset_size += len(special) if special else 0

    if charset_size == 0:
        return 0.0

    return math.log2(charset_size) * len(text)


def dictionary_check(passphrase: str) -> list[str]:
    """
    Check if the passphrase contains common weak words.

    Args:
        passphrase: The passphrase string (space-separated words or raw text).

    Returns:
        List of matched common words (lowercased).
    """
    words = passphrase.lower().replace("-", " ").replace("_", " ").split()
    return [w for w in words if w in _COMMON_WORDS]


def load_bip39_wordlist(language: str = "english") -> set[str]:
    """
    Load the BIP-39 wordlist for a given language by extracting from the generator.

    Returns:
        Set of all valid BIP-39 words for the language.
    """
    try:
        from bip_utils import Bip39WordsFileFinder

        lang_map = {
            "english": "english",
            "chinese_simplified": "chinese_simplified",
            "chinese_traditional": "chinese_traditional",
            "czech": "czech",
            "french": "french",
            "italian": "italian",
            "japanese": "japanese",
            "korean": "korean",
            "portuguese": "portuguese",
            "spanish": "spanish",
        }
        lang = lang_map.get(language.lower(), "english")
        finder = Bip39WordsFileFinder(lang)
        wordlist_file = finder.GetFilePath()
        with open(wordlist_file, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception:
        return set()


def check_passphrase_strength(
    passphrase: str,
    language: str = "english",
    check_dictionary: bool = True,
) -> PassphraseStrength:
    """
    Perform a full strength analysis on a passphrase.

    Scoring criteria (0-100):
      - Shannon entropy contribution (0-30 pts)
      - Charset entropy contribution (0-20 pts)
      - Word count bonus (0-20 pts)
      - BIP-39 validity bonus (0-15 pts)
      - Dictionary penalty (-15 pts per match)

    Args:
        passphrase: The passphrase to analyze.
        language: Expected BIP-39 language.
        check_dictionary: Whether to run common-word dictionary check.

    Returns:
        PassphraseStrength object with full analysis.
    """
    words = passphrase.strip().split()
    word_count = len(words)

    shannon = shannon_entropy(passphrase)
    charset = charset_entropy(passphrase)

    is_valid = validate_mnemonic(passphrase, language)

    dict_matches = dictionary_check(passphrase) if check_dictionary else []
    has_dict_words = len(dict_matches) > 0

    # Scoring
    score = 0

    # Shannon entropy: 0-30 points (cap at ~4.5 bits/char for max)
    score += min(30, int((shannon / 4.5) * 30))

    # Charset entropy: 0-20 points (cap at 256 bits for max)
    score += min(20, int((charset / 256.0) * 20))

    # Word count: 0-20 points
    if word_count >= 24:
        score += 20
    elif word_count >= 18:
        score += 15
    elif word_count >= 12:
        score += 10
    elif word_count >= 6:
        score += 5

    # BIP-39 validity bonus: 15 points
    if is_valid:
        score += 15

    # Dictionary penalty
    score -= len(dict_matches) * 15

    # Clamp to 0-100
    score = max(0, min(100, score))

    # Rating
    if score >= 80:
        rating = "strong"
    elif score >= 60:
        rating = "moderate"
    elif score >= 40:
        rating = "weak"
    else:
        rating = "very_weak"

    return PassphraseStrength(
        passphrase=passphrase,
        shannon_entropy=shannon,
        charset_entropy=charset,
        has_dictionary_words=has_dict_words,
        dictionary_matches=dict_matches,
        is_bip39_valid=is_valid,
        score=score,
        rating=rating,
        word_count=word_count,
    )
