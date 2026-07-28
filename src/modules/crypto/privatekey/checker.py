"""Private key format validation and analysis.

Validates detected private key strings against known formats
(WIF, hex, Base58, PEM) and reports format-specific metadata.
"""

import base64
import re
from typing import Any

# WIF prefixes: K/L (compressed) or 5 (uncompressed) for mainnet
_WIF_PATTERN = re.compile(r"^([5KL][1-9A-HJ-NP-Za-km-z]{50,51})$")
_HEX_32_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_0X_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
_BASE58_PATTERN = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{44,88}$")
_PEM_PATTERN = re.compile(
    r"-----BEGIN (?:EC |RSA )?PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+)-----END (?:EC |RSA )?PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_ENC_PATTERN = re.compile(
    r"-----BEGIN ENCRYPTED PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+)-----END ENCRYPTED PRIVATE KEY-----",
    re.DOTALL,
)

# Base58 alphabet (Bitcoin)
_BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


class KeyValidationResult:
    """Result of private key format validation."""

    def __init__(
        self,
        raw: str,
        detected_format: str | None,
        is_valid_format: bool,
        details: dict[str, Any],
    ):
        self.raw = raw
        self.detected_format = detected_format
        self.is_valid_format = is_valid_format
        self.details = details

    def to_dict(self) -> dict:
        return {
            "detected_format": self.detected_format,
            "is_valid_format": self.is_valid_format,
            "details": self.details,
        }

    def __repr__(self) -> str:
        return f"<KeyValidationResult(format='{self.detected_format}', " f"valid={self.is_valid_format})>"


def validate_wif(key: str) -> KeyValidationResult:
    """Validate a WIF (Wallet Import Format) private key.

    WIF keys:
    - Start with '5' (uncompressed) or 'K'/'L' (compressed)
    - Are Base58Check encoded
    - Decode to 32 or 33 bytes of key data

    Args:
        key: The WIF string to validate.

    Returns:
        KeyValidationResult with validation details.

    """
    key = key.strip()
    match = _WIF_PATTERN.match(key)
    if not match:
        return KeyValidationResult(
            raw=key,
            detected_format="wif",
            is_valid_format=False,
            details={"error": "Does not match WIF pattern"},
        )

    is_compressed = key[0] in ("K", "L")
    details: dict[str, Any] = {
        "compressed": is_compressed,
        "length": len(key),
        "prefix": key[0],
    }

    # Verify Base58 decodability
    try:
        decoded = _base58_decode(key)
        if len(decoded) not in (37, 38):
            details["warning"] = f"Unexpected decoded length: {len(decoded)} bytes"
        # Check checksum (last 4 bytes)
        if len(decoded) >= 4:
            import hashlib

            payload = decoded[:-4]
            checksum = decoded[-4:]
            computed = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            details["checksum_valid"] = checksum == computed
        else:
            details["checksum_valid"] = False
    except Exception as exc:
        details["decode_error"] = str(exc)
        details["checksum_valid"] = False

    return KeyValidationResult(
        raw=key,
        detected_format="wif",
        is_valid_format=True,
        details=details,
    )


def validate_hex_key(key: str) -> KeyValidationResult:
    """Validate a hex-encoded private key (32 bytes = 64 hex chars).

    Args:
        key: Hex string (optionally prefixed with 0x).

    Returns:
        KeyValidationResult with validation details.

    """
    key = key.strip()
    is_prefixed = key.startswith("0x")
    hex_part = key[2:] if is_prefixed else key

    is_valid = bool(_HEX_32_PATTERN.match(hex_part))
    if is_prefixed:
        is_valid = bool(_HEX_0X_PATTERN.match(key))

    details: dict[str, Any] = {
        "has_0x_prefix": is_prefixed,
        "length": len(hex_part),
    }

    if is_valid:
        # Check if it's not all zeros or all ones (trivially weak)
        details["trivially_weak"] = hex_part == "0" * 64 or hex_part == "f" * 64
        # Check valid range for secp256k1 (must be < curve order)
        try:
            key_int = int(hex_part, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            details["in_valid_range"] = 0 < key_int < secp256k1_order
        except ValueError:
            details["in_valid_range"] = False

    return KeyValidationResult(
        raw=key,
        detected_format="hex",
        is_valid_format=is_valid,
        details=details,
    )


def validate_base58_key(key: str) -> KeyValidationResult:
    """Validate a Base58-encoded key string.

    Args:
        key: Base58 string.

    Returns:
        KeyValidationResult with validation details.

    """
    key = key.strip()
    is_valid = bool(_BASE58_PATTERN.match(key))

    details: dict[str, Any] = {
        "length": len(key),
        "uses_base58_alphabet": all(c in _BASE58_ALPHABET for c in key),
    }

    if is_valid:
        try:
            decoded = _base58_decode(key)
            details["decoded_byte_length"] = len(decoded)
        except Exception as exc:
            details["decode_error"] = str(exc)

    return KeyValidationResult(
        raw=key,
        detected_format="base58",
        is_valid_format=is_valid,
        details=details,
    )


def validate_pem_key(pem_text: str) -> KeyValidationResult:
    """Validate a PEM-encoded private key.

    Args:
        pem_text: Full PEM block string.

    Returns:
        KeyValidationResult with validation details.

    """
    pem_text = pem_text.strip()
    is_encrypted = bool(_PEM_ENC_PATTERN.search(pem_text))
    match = _PEM_PATTERN.search(pem_text) or _PEM_ENC_PATTERN.search(pem_text)

    if not match:
        return KeyValidationResult(
            raw=pem_text[:80],
            detected_format="pem",
            is_valid_format=False,
            details={"error": "Does not match PEM private key pattern"},
        )

    b64_body = match.group(1).replace("\n", "").replace("\r", "").replace(" ", "")
    details: dict[str, Any] = {
        "encrypted": is_encrypted,
        "base64_length": len(b64_body),
    }

    # Verify valid base64
    try:
        decoded = base64.b64decode(b64_body)
        details["decoded_byte_length"] = len(decoded)
        # Detect key type heuristically from DER structure
        if decoded[:2] == b"\x30\x82":
            details["likely_type"] = "RSA"
        elif decoded[:2] == b"\x30\x81":
            details["likely_type"] = "EC"
        else:
            details["likely_type"] = "unknown"
    except Exception as exc:
        details["decode_error"] = str(exc)

    return KeyValidationResult(
        raw=pem_text[:80],
        detected_format="pem",
        is_valid_format=True,
        details=details,
    )


def validate_key(raw: str) -> KeyValidationResult:
    """Auto-detect and validate a private key string.

    Tries formats in order: PEM, WIF, hex (0x-prefixed), hex, Base58.

    Args:
        raw: The raw key string.

    Returns:
        KeyValidationResult for the first matching format, or
        a result with detected_format=None if no format matched.

    """
    raw = raw.strip()

    # PEM has distinctive headers
    if "-----BEGIN" in raw and "PRIVATE KEY-----" in raw:
        return validate_pem_key(raw)

    # WIF: starts with 5/K/L and specific length
    if _WIF_PATTERN.match(raw):
        return validate_wif(raw)

    # Hex with 0x prefix
    if _HEX_0X_PATTERN.match(raw):
        return validate_hex_key(raw)

    # Plain hex
    if _HEX_32_PATTERN.match(raw):
        return validate_hex_key(raw)

    # Base58 (broader pattern, try last)
    if _BASE58_PATTERN.match(raw) and len(raw) >= 44:
        return validate_base58_key(raw)

    return KeyValidationResult(
        raw=raw,
        detected_format=None,
        is_valid_format=False,
        details={"error": "No recognized private key format"},
    )


def _base58_decode(s: str) -> bytes:
    """Decode a Base58 string to bytes (Bitcoin-style)."""
    num = 0
    for char in s:
        num *= 58
        if char not in _BASE58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char!r}")
        num += "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".index(char)

    # Count leading '1's (each maps to a zero byte)
    leading_zeros = 0
    for char in s:
        if char == "1":
            leading_zeros += 1
        else:
            break

    result = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return b"\x00" * leading_zeros + result
