"""Crypto Private Key module: Leaked key detection and validation.

Uses regex-based detection for WIF/hex/Base58/PEM formats
with optional GitHound subprocess integration.
"""

from src.modules.crypto.privatekey.scanner import (
    PrivateKeyScanner,
    detect_key_format,
    scan_file,
)
from src.modules.crypto.privatekey.checker import (
    validate_key,
    validate_wif,
    validate_hex_key,
    validate_base58_key,
    validate_pem_key,
    KeyValidationResult,
)

__all__ = [
    "PrivateKeyScanner",
    "detect_key_format",
    "scan_file",
    "validate_key",
    "validate_wif",
    "validate_hex_key",
    "validate_base58_key",
    "validate_pem_key",
    "KeyValidationResult",
]
