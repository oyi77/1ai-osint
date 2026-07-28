"""BIP-39 mnemonic passphrase generator using bip-utils.

Generates standards-compliant mnemonic seed phrases with configurable
word counts (12, 15, 18, 21, 24 words) and language support.
"""

from __future__ import annotations

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicGenerator,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39WordsNum,
)

# Map word count to bip-utils enum
_WORD_COUNT_MAP: dict[int, Bip39WordsNum] = {
    12: Bip39WordsNum.WORDS_NUM_12,
    15: Bip39WordsNum.WORDS_NUM_15,
    18: Bip39WordsNum.WORDS_NUM_18,
    21: Bip39WordsNum.WORDS_NUM_21,
    24: Bip39WordsNum.WORDS_NUM_24,
}

# Map language string to bip-utils enum
_LANGUAGE_MAP: dict[str, Bip39Languages] = {
    "english": Bip39Languages.ENGLISH,
    "chinese_simplified": Bip39Languages.CHINESE_SIMPLIFIED,
    "chinese_traditional": Bip39Languages.CHINESE_TRADITIONAL,
    "czech": Bip39Languages.CZECH,
    "french": Bip39Languages.FRENCH,
    "italian": Bip39Languages.ITALIAN,
    "korean": Bip39Languages.KOREAN,
    "portuguese": Bip39Languages.PORTUGUESE,
    "spanish": Bip39Languages.SPANISH,
}

VALID_WORD_COUNTS = list(_WORD_COUNT_MAP.keys())
VALID_LANGUAGES = list(_LANGUAGE_MAP.keys())


class MnemonicGenerationError(Exception):
    """Raised when mnemonic generation fails."""


class MnemonicValidationError(Exception):
    """Raised when mnemonic validation fails."""


def generate_mnemonic(
    word_count: int = 24,
    language: str = "english",
    entropy: bytes | None = None,
) -> str:
    """Generate a BIP-39 mnemonic phrase.

    Args:
        word_count: Number of words (12, 15, 18, 21, or 24).
        language: BIP-39 wordlist language.
        entropy: Optional custom entropy bytes. If None, uses
                 cryptographically secure random (secrets.token_bytes).

    Returns:
        Space-separated mnemonic phrase string.

    Raises:
        MnemonicGenerationError: If word_count or language is invalid.

    """
    if word_count not in _WORD_COUNT_MAP:
        raise MnemonicGenerationError(f"Invalid word count {word_count}. Must be one of {VALID_WORD_COUNTS}")

    lang_key = language.lower()
    if lang_key not in _LANGUAGE_MAP:
        raise MnemonicGenerationError(f"Invalid language '{language}'. Must be one of {VALID_LANGUAGES}")

    words_num = _WORD_COUNT_MAP[word_count]
    lang_enum = _LANGUAGE_MAP[lang_key]

    try:
        if entropy is not None:
            mnemonic = Bip39MnemonicGenerator(lang_enum).FromEntropy(entropy)
        else:
            mnemonic = Bip39MnemonicGenerator(lang_enum).FromWordsNumber(words_num)
        return mnemonic.ToStr()
    except Exception as exc:
        raise MnemonicGenerationError(f"Failed to generate mnemonic: {exc}") from exc


def validate_mnemonic(mnemonic: str, language: str = "english") -> bool:
    """Validate a BIP-39 mnemonic phrase (checksum + wordlist membership).

    Args:
        mnemonic: Space-separated mnemonic phrase.
        language: Expected language for the wordlist.

    Returns:
        True if the mnemonic is valid, False otherwise.

    """
    lang_key = language.lower()
    if lang_key not in _LANGUAGE_MAP:
        return False

    try:
        lang_enum = _LANGUAGE_MAP[lang_key]
        validator = Bip39MnemonicValidator(lang_enum)
        return validator.IsValid(mnemonic)
    except Exception:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive a 512-bit seed from a BIP-39 mnemonic.

    Args:
        mnemonic: Valid BIP-39 mnemonic phrase.
        passphrase: Optional extra passphrase for seed derivation (BIP-39 salt).

    Returns:
        64-byte seed bytes.

    """
    return Bip39SeedGenerator(mnemonic).Generate(passphrase)


def generate_with_details(
    word_count: int = 24,
    language: str = "english",
) -> dict:
    """Generate a mnemonic with full metadata for OSINT reporting.

    Returns:
        Dict with keys: mnemonic, word_count, language, entropy_bits,
        is_valid, word_list.

    """
    mnemonic = generate_mnemonic(word_count=word_count, language=language)
    words = mnemonic.split()

    # Entropy bits = (word_count / 3) * 32
    entropy_bits = (word_count * 32) // 3

    return {
        "mnemonic": mnemonic,
        "word_count": len(words),
        "language": language,
        "entropy_bits": entropy_bits,
        "is_valid": validate_mnemonic(mnemonic, language),
        "word_list": words,
    }
