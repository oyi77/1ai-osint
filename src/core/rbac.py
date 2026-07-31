"""Role-Based Access Control (RBAC) — per-tier access to data sources.

Blueprint Layer 3: every source carries a minimum ``AccessTier``; a
requester must hold a tier at least as privileged to query it. This is the
"RBAC per tier" gap item from the gap analysis §7 (previously: single auth
token, no tiering).

Tiers (low → high privilege):

- ``READONLY`` — read-only consumer of low-sensitivity sources
  (government open data, public API data, legitimate-interest OSINT).
- ``ANALYST`` — can run structured investigations across most sources.
- ``ADMIN`` — sole tier allowed for consent-required sources (Pasal 4.2
  UU PDP) and undocumented/paid breach databases.

Resolution: bearer tokens map to tiers via ``WEB_AUTH_TOKENS``
(``tier:token,tier:token``) with ``WEB_AUTH_TOKEN`` as the legacy admin
token. Unknown tokens resolve to ``None`` (unauthorized).
"""

from __future__ import annotations

import os
import secrets
from enum import IntEnum


class AccessTier(IntEnum):
    """Access tiers ordered by privilege (higher = more privileged)."""

    READONLY = 10
    ANALYST = 20
    ADMIN = 30

    @classmethod
    def from_str(cls, value: str | None) -> "AccessTier":
        """Parse a tier name (case-insensitive), defaulting to READONLY."""
        if not value:
            return cls.READONLY
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return cls.READONLY


def tier_allows(requester_tier: AccessTier, required_tier: AccessTier) -> bool:
    """True if ``requester_tier`` is at least ``required_tier``."""
    return requester_tier >= required_tier


# ── Token → tier resolution ──────────────────────────────────────────────────

#: Legacy single-token auth (WEB_AUTH_TOKEN) is treated as ADMIN for
#: backward compatibility with pre-RBAC deployments.
_LEGACY_TOKEN = os.environ.get("WEB_AUTH_TOKEN", "").strip()

#: WEB_AUTH_TOKENS = "readonly:tok1,admin:tok2" — higher privilege wins if a
#: token appears under multiple tiers.
_TOKEN_TIERS: dict[str, AccessTier] = {}
for _pair in os.environ.get("WEB_AUTH_TOKENS", "").split(","):
    _pair = _pair.strip()
    if not _pair or ":" not in _pair:
        continue
    _tier_name, _, _token = _pair.partition(":")
    _tier = AccessTier.from_str(_tier_name.strip())
    _token = _token.strip()
    if _token:
        if _token in _TOKEN_TIERS and _tier < _TOKEN_TIERS[_token]:
            continue  # keep the highest privilege mapping
        _TOKEN_TIERS[_token] = _tier
if _LEGACY_TOKEN:
    _TOKEN_TIERS[_LEGACY_TOKEN] = AccessTier.ADMIN


def tier_for_token(token: str | None) -> AccessTier | None:
    """Resolve the access tier for a bearer token.

    Returns ``None`` for an unknown/absent token (the caller is
    unauthenticated and must be rejected at the auth boundary).
    """
    if not token:
        return None
    return _TOKEN_TIERS.get(token)


def token_is_valid(token: str | None) -> bool:
    """Timing-safe check that the token is a known one."""
    if not token:
        return False
    return any(secrets.compare_digest(token, known) for known in _TOKEN_TIERS)


def list_tiers() -> list[str]:
    """Return tier names for introspection/debugging."""
    return [t.name for t in AccessTier]
