"""E.164 phone normalization utilities."""

from __future__ import annotations

import re

_DIGITS_RE = re.compile(r"\D+")


def normalize_phone_e164(value: str, default_region: str = "ID") -> str | None:
    """Best-effort E.164 normalization (Indonesia-friendly default)."""
    if not value or not str(value).strip():
        return None
    digits = _DIGITS_RE.sub("", str(value))
    if not digits or len(digits) < 7:
        return None
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0") and default_region == "ID":
        digits = "62" + digits[1:]
    if len(digits) >= 10:
        return f"+{digits}"
    return None


# Official Indonesian mobile number prefixes (4-digit), per operator.
# Source: publicly published operator ranges (Telkomsel, Indosat Ooredoo,
# XL Axiata, AXIS, Tri, Smartfren).
ID_CARRIER_PREFIXES: dict[str, str] = {
    "0811": "Telkomsel",
    "0812": "Telkomsel",
    "0813": "Telkomsel",
    "0821": "Telkomsel",
    "0822": "Telkomsel",
    "0823": "Telkomsel",
    "0851": "Telkomsel",
    "0852": "Telkomsel",
    "0853": "Telkomsel",
    "0814": "Indosat Ooredoo",
    "0815": "Indosat Ooredoo",
    "0816": "Indosat Ooredoo",
    "0855": "Indosat Ooredoo",
    "0856": "Indosat Ooredoo",
    "0857": "Indosat Ooredoo",
    "0858": "Indosat Ooredoo",
    "0817": "XL Axiata",
    "0818": "XL Axiata",
    "0819": "XL Axiata",
    "0859": "XL Axiata",
    "0877": "XL Axiata",
    "0878": "XL Axiata",
    "0879": "XL Axiata",
    "0831": "AXIS",
    "0832": "AXIS",
    "0833": "AXIS",
    "0895": "Tri",
    "0896": "Tri",
    "0897": "Tri",
    "0898": "Tri",
    "0899": "Tri",
    "0881": "Smartfren",
    "0882": "Smartfren",
    "0883": "Smartfren",
    "0884": "Smartfren",
    "0885": "Smartfren",
    "0886": "Smartfren",
    "0887": "Smartfren",
    "0888": "Smartfren",
}


def lookup_id_carrier(e164: str) -> str | None:
    """Return the Indonesian mobile carrier for an E.164 number, if known.

    Deterministic and offline-safe: uses the operator prefix registry above,
    so it works even when a lookup provider returns no carrier metadata.
    Returns ``None`` for non-Indonesian, landline, or unknown numbers.

    Args:
        e164: E.164 formatted number (e.g. ``+6281234567890``)

    """
    national = e164.removeprefix("+").removeprefix("62")
    if not national.startswith("8"):
        return None
    local = "0" + national
    return ID_CARRIER_PREFIXES.get(local[:4])
