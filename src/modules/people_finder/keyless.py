"""Keyless social media probe provider for People Finder.

This provider is the 0-API-priority fallback: when no external username
enumeration CLI (Sherlock/Maigret/WhatsMyName) is installed, we probe a
small set of public, keyless endpoints directly. Every outbound call goes
through the shared :class:`~src.core.rate_limiter.RateLimiter` and
:class:`~src.core.cache.Cache` so it honours the repo-wide conventions for
external traffic.

The provider speaks the Sherlock result format::

    {"github": {"url": "...", "status": "found", "username": "octocat"}}

so the existing ``PeopleFinderSearch`` parser consumes it unchanged.
"""

from __future__ import annotations

from typing import Callable

import httpx

from src.core.cache import Cache
from src.core.rate_limiter import RateLimiter

# (platform, url template, found-if) probes. ``found-if`` is a callable that
# decides whether the HTTP response represents an existing account.
_ENDPOINTS: dict[str, tuple[str, Callable[[int], bool]]] = {
    "github": (
        "https://api.github.com/users/{username}",
        lambda status: status == 200,
    ),
    "gitlab": (
        "https://gitlab.com/api/v4/users?username={username}",
        lambda status: status == 200,
    ),
    "keybase": (
        "https://keybase.io/_/api/1.0/user/lookup.json?username={username}",
        lambda status: status == 200,
    ),
    "mastodon": (
        "https://mastodon.social/api/v1/accounts/lookup?acct={username}",
        lambda status: status == 200,
    ),
    "reddit": (
        "https://www.reddit.com/user/{username}/about.json",
        lambda status: status == 200,
    ),
}

_CACHE_TTL = 24 * 3600  # 24h — probes are cheap but still honour the cache


class KeylessSocialProvider:
    """Probe keyless public endpoints for a username (Sherlock format)."""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self._limiter = RateLimiter()
        self._cache = Cache()

    def search(self, username: str) -> dict:
        """Return found profiles in Sherlock format, or ``{"error": ...}``
        when no probe could reach the network at all."""
        found: dict = {}
        reached_network = False
        errors: list[str] = []

        headers = {
            "User-Agent": "1ai-osint/0.1.0 (keyless probe)",
            "Accept": "application/json",
        }
        with httpx.Client(timeout=self.timeout, follow_redirects=True, headers=headers) as client:
            for platform, (url_template, found_if) in _ENDPOINTS.items():
                url = url_template.format(username=username)
                cache_key = f"keyless_social:{platform}:{username}"
                cached = self._cache.get(cache_key)
                if cached is not None:
                    if cached.get("found"):
                        found[platform] = {
                            "url": cached.get("url", url),
                            "status": "found",
                            "username": username,
                        }
                    continue

                try:
                    # Blocking wait is fine here: providers run in an executor thread.
                    self._limiter.wait("keyless_social")
                    resp = client.get(url)
                    reached_network = True
                except httpx.HTTPError as exc:
                    errors.append(f"{platform}: {exc}")
                    continue

                profile_url = str(resp.url)
                if found_if(resp.status_code):
                    found[platform] = {
                        "url": profile_url,
                        "status": "found",
                        "username": username,
                    }
                    self._cache.set(cache_key, {"found": True, "url": profile_url}, ttl=_CACHE_TTL)
                else:
                    # Only cache definitive negatives (404s); leave 429/5xx
                    # uncached so a transient block does not poison the result.
                    if resp.status_code == 404:
                        self._cache.set(cache_key, {"found": False}, ttl=_CACHE_TTL)

        if not reached_network:
            return {"error": "; ".join(errors) or "all keyless probes failed"}
        return found
