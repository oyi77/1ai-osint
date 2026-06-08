"""Identifier extractor — extracts new identifiers from scan results."""

from __future__ import annotations

import logging
import re

from src.modules.deep_scan import Identifier, IdentifierType

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}")
_DOMAIN_RE = re.compile(
    r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)
_BTC_RE = re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}")
_ETH_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_NIK_RE = re.compile(r"\b\d{16}\b")


def extract_identifiers(text: str, source: str) -> list[Identifier]:
    """Extract all identifiable information from raw text."""
    identifiers: list[Identifier] = []
    seen: set[str] = set()

    # Emails
    for match in _EMAIL_RE.findall(text):
        key = f"email:{match.lower()}"
        if key not in seen:
            seen.add(key)
            identifiers.append(
                Identifier(
                    value=match.lower(),
                    id_type=IdentifierType.EMAIL,
                    source=source,
                )
            )

    # Phone numbers
    for match in _PHONE_RE.findall(text):
        cleaned = re.sub(r"[\s\-\.\(\)]", "", match)
        if len(cleaned) >= 7:
            key = f"phone:{cleaned}"
            if key not in seen:
                seen.add(key)
                identifiers.append(
                    Identifier(
                        value=cleaned,
                        id_type=IdentifierType.PHONE,
                        source=source,
                    )
                )

    # Domains
    for match in _DOMAIN_RE.findall(text):
        key = f"domain:{match.lower()}"
        if key not in seen:
            seen.add(key)
            identifiers.append(
                Identifier(
                    value=match.lower(),
                    id_type=IdentifierType.DOMAIN,
                    source=source,
                )
            )

    # Ethereum addresses
    for match in _ETH_RE.findall(text):
        key = f"crypto:{match.lower()}"
        if key not in seen:
            seen.add(key)
            identifiers.append(
                Identifier(
                    value=match,
                    id_type=IdentifierType.CRYPTO_ADDRESS,
                    source=source,
                    metadata={"chain": "ethereum"},
                )
            )

    # Bitcoin addresses
    for match in _BTC_RE.findall(text):
        key = f"crypto:{match}"
        if key not in seen:
            seen.add(key)
            identifiers.append(
                Identifier(
                    value=match,
                    id_type=IdentifierType.CRYPTO_ADDRESS,
                    source=source,
                    metadata={"chain": "bitcoin"},
                )
            )

    # Indonesian NIK (16 digits)
    for match in _NIK_RE.findall(text):
        if _is_valid_nik(match):
            key = f"nik:{match}"
            if key not in seen:
                seen.add(key)
                identifiers.append(
                    Identifier(
                        value=match,
                        id_type=IdentifierType.NIK,
                        source=source,
                        metadata=_parse_nik(match),
                    )
                )

    return identifiers


def extract_usernames_from_profiles(findings: list) -> list[Identifier]:
    """Extract usernames and confirmed profiles from social OSINT findings."""
    identifiers: list[Identifier] = []
    seen: set[str] = set()

    for finding in findings:
        raw = finding.raw_data or {}
        uname = raw.get("username")
        if isinstance(uname, str) and uname.strip():
            key = f"user:{uname.lower()}"
            if key not in seen:
                seen.add(key)
                from src.modules.deep_scan.name_pivots import slugify_username

                handle = slugify_username(uname) if " " in uname else uname.strip()
                if handle:
                    identifiers.append(
                        Identifier(
                            value=handle,
                            id_type=IdentifierType.USERNAME,
                            source=finding.module,
                            confidence=0.9,
                        )
                    )

    return identifiers


def username_from_profile_url(url: str) -> str | None:
    """Extract handle from a canonical social profile URL."""
    if not url or "://" not in url:
        return None
    path = url.split("://", 1)[-1].split("/", 1)
    if len(path) < 2:
        return None
    tail = path[1].strip("/").split("/")
    if not tail:
        return None
    handle = tail[-1].lstrip("@")
    if handle and " " not in handle and len(handle) <= 50:
        return handle
    return None


def _is_valid_nik(nik: str) -> bool:
    """Validate Indonesian NIK format."""
    if len(nik) != 16:
        return False
    province = int(nik[:2])
    city = int(nik[2:4])
    if province < 11 or province > 99:
        return False
    if city < 1 or city > 99:
        return False
    return True


def _parse_nik(nik: str) -> dict:
    """Parse Indonesian NIK into components."""
    province_code = nik[:2]
    city_code = nik[2:4]
    region_code = nik[4:6]
    day = int(nik[6:8])
    month = int(nik[8:10])
    year = int(nik[10:12])

    gender = "male"
    if day > 40:
        gender = "female"
        day -= 40

    # Determine century
    if year <= 25:
        full_year = 2000 + year
    else:
        full_year = 1900 + year

    return {
        "province_code": province_code,
        "city_code": city_code,
        "region_code": region_code,
        "birth_day": day,
        "birth_month": month,
        "birth_year": full_year,
        "gender": gender,
    }
