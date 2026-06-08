"""Crypto Passphrase module: BIP-39 generation + entropy analysis.

Uses bip-utils for standards-compliant mnemonic generation.
DO NOT implement crypto primitives from scratch.
"""

from src.modules.crypto.passphrase.checker import (
    PassphraseStrength,
    charset_entropy,
    check_passphrase_strength,
    dictionary_check,
    shannon_entropy,
)
from src.modules.crypto.passphrase.generator import (
    VALID_LANGUAGES,
    VALID_WORD_COUNTS,
    generate_mnemonic,
    generate_with_details,
    mnemonic_to_seed,
    validate_mnemonic,
)

__all__ = [
    "generate_mnemonic",
    "generate_with_details",
    "mnemonic_to_seed",
    "validate_mnemonic",
    "VALID_WORD_COUNTS",
    "VALID_LANGUAGES",
    "check_passphrase_strength",
    "shannon_entropy",
    "charset_entropy",
    "dictionary_check",
    "PassphraseStrength",
]
