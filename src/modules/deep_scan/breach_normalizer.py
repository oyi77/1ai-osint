"""Normalize breach/leak records to INTEL_STANDARD field taxonomy."""
from __future__ import annotations

import re
from typing import Any

# Canonical field keys (INTEL_STANDARD.md)
_CANONICAL_ALIASES: dict[str, tuple[str, ...]] = {
    "email": ("email", "mail", "e_mail", "user_email"),
    "username": ("username", "user", "nick", "login", "handle"),
    "phone": ("phone", "phone_number", "telephone", "mobile", "msisdn"),
    "full_name": ("full_name", "name", "fullname", "display_name"),
    "password": ("password", "pass", "passwd"),
    "password_hash": ("password_hash", "hash", "encrypted_password", "hashed_password"),
    "salt": ("salt", "password_salt"),
    "ip_address": ("ip_address", "ip", "lastip", "ipaddress"),
    "address": ("address", "adres", "street", "home_address"),
    "city": ("city", "town", "locality"),
    "region": ("region", "state", "province", "district"),
    "country": ("country", "nation"),
    "gender": ("gender", "sex"),
    "date_of_birth": ("date_of_birth", "dob", "birth_date", "birthday", "bday"),
    "nik": ("nik", "national_id", "ktp", "identity_number"),
    "passport_number": ("passport_number", "passport", "passport_no"),
    "breach_name": ("breach_name", "breach", "source_breach", "database"),
    "breach_date": ("breach_date", "breachdate", "leak_date"),
    "domain": ("domain", "website", "site"),
    "registration_date": ("registration_date", "reg_date", "date_registered", "created"),
    "last_activity": ("last_activity", "last_seen", "last_login"),
    "job_title": ("job_title", "title", "position"),
    "company_name": ("company_name", "company", "employer", "organization"),
    "crypto_address": ("crypto_address", "wallet", "btc_address", "eth_address"),
}


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", key.lower()).strip("_")


def normalize_breach_record(raw: dict[str, Any]) -> dict[str, str]:
    """Map arbitrary leak fields to canonical INTEL_STANDARD keys."""
    if not raw:
        return {}
    out: dict[str, str] = {}
    normalized_input = {_normalize_key(k): str(v) for k, v in raw.items() if v is not None}

    for canonical, aliases in _CANONICAL_ALIASES.items():
        for alias in aliases:
            nk = _normalize_key(alias)
            if nk in normalized_input and normalized_input[nk].strip():
                out[canonical] = normalized_input[nk].strip()
                break

    for nk, val in normalized_input.items():
        if nk.startswith("_") or not val.strip():
            continue
        if not any(nk == _normalize_key(a) for aliases in _CANONICAL_ALIASES.values() for a in aliases):
            out.setdefault(nk, val.strip())

    return out
