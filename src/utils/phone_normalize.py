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
