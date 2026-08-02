"""JWT session tokens + per-route tier enforcement for the 1ai-osint Web UI.

Upgrade over static bearer tokens (blueprint Layer 3): a caller can exchange
a static tier token for a short-lived JWT carrying an ``exp`` and a ``tier``
claim. The middleware accepts both static tokens (backward compatible) and
JWTs. Routes that need stronger guarantees can require a minimum tier via
the :func:`require_tier` FastAPI dependency, which 403s callers below the
threshold.

Config (env vars, read lazily so runtime/test changes are honored):
    JWT_SECRET    — HMAC signing key. Unset → JWT login is disabled and
                    ``require_tier`` still works (it gates on the static-token
                    tier resolved by the middleware).
    JWT_TTL_HOURS — token lifetime in hours (default 24).
"""

from __future__ import annotations

import datetime as _dt
import hmac
import os
from typing import Any

from fastapi import HTTPException, Request, status

from src.core.rbac import AccessTier


def _jwt_secret() -> str:
    return os.environ.get("JWT_SECRET", "").strip()


def _jwt_ttl() -> _dt.timedelta:
    try:
        return _dt.timedelta(hours=int(os.environ.get("JWT_TTL_HOURS", "24")))
    except ValueError:
        return _dt.timedelta(hours=24)


def jwt_enabled() -> bool:
    """True when JWT login is configured (JWT_SECRET set)."""
    return bool(_jwt_secret())


def issue_token(token: str, tier: AccessTier) -> str:
    """Mint a signed JWT for an authenticated static token.

    Args:
        token: The static bearer token being exchanged.
        tier:  Access tier to encode in the ``tier`` claim.

    Returns:
        Compact JWS string (HS256) with ``exp`` and ``tier`` claims.

    Raises:
        RuntimeError: If JWT_SECRET is not configured.
    """
    secret = _jwt_secret()
    if not secret:
        raise RuntimeError("JWT_SECRET not configured — cannot issue tokens")

    import jwt as pyjwt

    now = _dt.datetime.now(_dt.timezone.utc)
    payload: dict[str, Any] = {
        "sub": _jwt_subject(token),
        "tier": tier.name.lower(),
        "iat": now,
        "exp": now + _jwt_ttl(),
    }
    return pyjwt.encode(payload, secret, algorithm="HS256")


def verify_token(token: str) -> AccessTier | None:
    """Verify a JWT and return its tier, or None when invalid/expired."""
    secret = _jwt_secret()
    if not secret or "." not in token:
        return None
    import jwt as pyjwt

    try:
        payload = pyjwt.decode(token, secret, algorithms=["HS256"])
    except pyjwt.PyJWTError:
        return None
    tier_name = str(payload.get("tier", "")).upper()
    return AccessTier.from_str(tier_name) if tier_name else None


def _jwt_subject(token: str) -> str:
    """Deterministic subject derived from the exchanged static token."""
    return hmac.new(_jwt_secret().encode(), token.encode(), "sha256").hexdigest()[:16]


# ---------------------------------------------------------------------------
# Per-route tier enforcement
# ---------------------------------------------------------------------------


def require_tier(min_tier: AccessTier):
    """FastAPI dependency factory: reject callers below *min_tier*.

    Reads the tier the AuthMiddleware resolved into ``request.scope``.
    When auth is disabled entirely the middleware never runs and the scope
    has no tier — fail closed with 403 rather than trusting the caller.

    Usage::

        @router.get("/secrets")
        async def secrets(_: None = Depends(require_tier(AccessTier.ADMIN))):
            ...
    """

    async def _dependency(request: Request) -> None:
        tier: AccessTier | None = request.scope.get("auth_tier")
        if tier is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Authentication required",
            )
        if tier < min_tier:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires tier {min_tier.name.lower()}, got {tier.name.lower()}",
            )

    return _dependency
