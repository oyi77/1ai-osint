"""ToS guard — per-source rate-limit enforcement (blueprint Layer 3).

Gap item "ToS guard per source: rate-limit awareness per platform ToS":
each source's compliance registry entry carries a ``requests_per_minute``
ceiling; this guard enforces it before every external query using the
existing token-bucket ``RateLimiter`` keyed per source.

Semantics: ``tos_allows(source)`` returns True if the query may proceed
immediately. When the bucket is empty the guard returns False — the caller
skips the query (and the audit trail records ``outcome="throttled"``) rather
than hammering the platform and risking a ToS violation / IP ban.

Each source gets its own ``RateLimiter`` instance (its own token bucket at
the source's configured rate) so async callers never race on shared state.
All instances persist to the same state file, keyed per source.
"""

from __future__ import annotations

import logging
from pathlib import Path

from src.core.compliance import requests_per_minute_for
from src.core.config import settings
from src.core.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

#: Burst ceiling per source (tokens above the sustained per-minute rate).
_DEFAULT_BURST = 5

_limiters: dict[str, RateLimiter] = {}


def _get_limiter(source_name: str) -> RateLimiter:
    """Return the per-source token-bucket limiter (lazily created)."""
    if source_name not in _limiters:
        path = Path(settings.rate_limit_file)
        if not path.is_absolute():
            path = settings.project_root / path
        rpm = max(1, requests_per_minute_for(source_name))
        _limiters[source_name] = RateLimiter(
            state_file=path,
            requests_per_minute=rpm,
            burst=max(_DEFAULT_BURST, rpm // 4),
        )
    return _limiters[source_name]


def tos_allows(source_name: str) -> bool:
    """True if the query may proceed under the source's ToS rate ceiling.

    Consumes one token from the per-source bucket. Returns False when the
    bucket is empty — the caller must skip the query.
    """
    # Key the token bucket by source name: all per-source limiter instances
    # share one state file, so an unkeyed acquire would make every source
    # draw from the same "default" bucket (first source exhausts the rest).
    wait = _get_limiter(source_name).acquire(key=source_name)
    if wait > 0:
        logger.debug(
            "ToS guard: source %s rate-limited (%.2fs wait) — throttling",
            source_name,
            wait,
        )
        return False
    return True


def reset_guard() -> None:
    """Reset all per-source limiters (test isolation)."""
    for limiter in _limiters.values():
        limiter.reset()
    _limiters.clear()
