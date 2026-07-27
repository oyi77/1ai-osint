"""Breach source router — keyed APIs with dynamic discovery, health checks, and fallback chains.

Provides ``configured_breach_modules()`` and ``breach_status_report()`` for
backward compatibility alongside the richer ``BreachRouter`` class that adds
dynamic source discovery, environment variable auto-configuration, health
checking, rate limiting, and fallback chains.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from src.core.config import Settings

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Backward-compatible constants and functions
# ------------------------------------------------------------------

# Maps deep-scan module name → Settings field
BREACH_API_KEYS: dict[str, str] = {
    "hibp": "hibp_api_key",
    "leakcheck": "leakcheck_api_key",
    "dehashed": "dehashed_api_key",
    "snusbase": "snusbase_api_key",
    "snylla": "scylla_api_key",
    "intelx": "intelx_api_key",
}


def configured_breach_modules(settings: Settings | None = None) -> list[str]:
    """Return breach module names that have non-empty API keys."""
    cfg = settings or Settings()
    out: list[str] = []
    for module, field in BREACH_API_KEYS.items():
        if (getattr(cfg, field, "") or "").strip():
            out.append(module)
    return out


def breach_status_report(
    settings: Settings | None = None,
) -> list[tuple[str, bool, str]]:
    """For doctor: (module, configured, env_var)."""
    cfg = settings or Settings()
    return [
        (mod, bool((getattr(cfg, field, "") or "").strip()), field.upper()) for mod, field in BREACH_API_KEYS.items()
    ]


# ------------------------------------------------------------------
# Additional known breach sources (used by dynamic discovery)
# ------------------------------------------------------------------

# Sources discoverable from .env even if not in BREACH_API_KEYS above.
_DISCOVERABLE_VARS: dict[str, str] = {
    "breachdirectory": "breachdirectory_api_key",
    "chiasmodon": "chiasmodon_token",
}

# Fallback chains: if the primary source fails, try these in order.
DEFAULT_FALLBACK_CHAINS: dict[str, list[str]] = {
    "hibp": ["dehashed", "leakcheck"],
    "dehashed": ["leakcheck", "snusbase"],
    "leakcheck": ["snusbase", "intelx"],
    "snusbase": ["intelx", "scylla"],
    "scylla": ["intelx"],
    "intelx": [],
    "breachdirectory": ["dehashed", "leakcheck"],
    "chiasmodon": [],
}


# ------------------------------------------------------------------
# BreachRouter
# ------------------------------------------------------------------


class BreachRouter:
    """Dynamic breach source router with health checks, rate limiting and fallback chains.

    Compared to the static ``configured_breach_modules()``, this class:

    * Discovers sources dynamically from environment variables.
    * Supports auto-configuration from ``.env``.
    * Health-checks each source (is the API reachable?).
    * Enforces per-source rate limits.
    * Chains fallbacks when a source fails.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        storage_dir: Path | str | None = None,
    ):
        self._cfg = settings or Settings()
        self._rate_limit_state: dict[str, float] = {}
        self._health_cache: dict[str, bool] = {}
        self._storage_dir = Path(storage_dir) if storage_dir else Path("investigations") / "breach_router"
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # source discovery
    # ------------------------------------------------------------------

    def discover_sources(self) -> dict[str, str]:
        """Discover all configured breach sources from environment variables.

        Returns ``{module_name: settings_field_name}`` for every source
        that has a non-empty API key in the current environment.
        """
        discovered: dict[str, str] = {}

        # Static known sources
        for module, field in BREACH_API_KEYS.items():
            if self._has_key(field):
                discovered[module] = field

        # Dynamically discoverable sources
        for module, field in _DISCOVERABLE_VARS.items():
            if self._has_key(field) and module not in discovered:
                discovered[module] = field

        return discovered

    def discover_sources_from_env(self, env_path: str | Path | None = None) -> dict[str, str]:
        """Scan a ``.env`` file (or current environment) for breach API keys.

        Returns every module→field mapping where the key is non-empty.
        """
        if env_path:
            import os

            from dotenv import load_dotenv

            load_dotenv(dotenv_path=str(env_path))
            # Re-read from env
            for module, field in {**BREACH_API_KEYS, **_DISCOVERABLE_VARS}.items():
                val = os.environ.get(field.upper(), "") or os.environ.get(field, "")
                if val and val.strip():
                    self._set_attr(module, val)

        return self.discover_sources()

    # ------------------------------------------------------------------
    # health checks
    # ------------------------------------------------------------------

    def health_check(self, module: str) -> bool:
        """Check if a breach source's API is reachable (cached per session).

        The actual check depends on the module:
        * Known endpoints are contacted with a lightweight HEAD.
        * Unknown modules return False.
        """
        if module in self._health_cache:
            return self._health_cache[module]

        try:
            import httpx

            endpoints: dict[str, str] = {
                "hibp": "https://haveibeenpwned.com/api/v3/breaches",
                "dehashed": "https://api.dehashed.com",
                "leakcheck": "https://leakcheck.io/api/v2/check",
                "snusbase": "https://api.snusbase.com",
                "intelx": "https://2.intelx.io/health",
                "scylla": "https://scylla.so",
                "breachdirectory": "https://breachdirectory.org/api/v1/health",
            }
            endpoint = endpoints.get(module)
            if not endpoint:
                self._health_cache[module] = False
                return False

            resp = httpx.get(endpoint, timeout=10.0)
            ok = resp.is_success or resp.status_code == 429  # 429 = reachable but rate-limited
            self._health_cache[module] = ok
            return ok
        except Exception as exc:
            logger.debug("Health check failed for %s: %s", module, exc)
            self._health_cache[module] = False
            return False

    def health_report(self) -> dict[str, bool]:
        """Return health status for all configured sources."""
        sources = self.discover_sources()
        return {mod: self.health_check(mod) for mod in sources}

    # ------------------------------------------------------------------
    # rate limiting
    # ------------------------------------------------------------------

    def rate_limit(self, module: str, min_interval_seconds: float = 1.5) -> bool:
        """Enforce a per-source rate limit.

        Returns True if the call is allowed now, False if it should be
        deferred.
        """
        now = time.monotonic()
        last = self._rate_limit_state.get(module, 0.0)
        if now - last < min_interval_seconds:
            return False
        self._rate_limit_state[module] = now
        return True

    def wait_until_allowed(self, module: str, min_interval: float = 1.5) -> None:
        """Block until the rate limit for *module* allows a call."""
        while not self.rate_limit(module, min_interval):
            time.sleep(0.25)

    # ------------------------------------------------------------------
    # fallback chain
    # ------------------------------------------------------------------

    def fallback_chain(self, module: str) -> list[str]:
        """Return the ordered fallback chain for a given source."""
        return DEFAULT_FALLBACK_CHAINS.get(module, [])

    def resolve_source(self, module: str) -> str | None:
        """Resolve a module name to the first available source.

        Checks the primary module, then walks the fallback chain until
        a configured, healthy source is found.

        Returns the source module name, or ``None`` if nothing is available.
        """
        if self._is_configured(module) and self.health_check(module):
            return module

        for fallback in self.fallback_chain(module):
            if self._is_configured(fallback) and self.health_check(fallback):
                return fallback

        return None

    def resolve_all(self) -> dict[str, str | None]:
        """Resolve every configured source to its best available endpoint.

        Returns ``{primary: resolved_or_None}``.
        """
        sources = self.discover_sources()
        return {mod: self.resolve_source(mod) for mod in sources}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _has_key(self, field: str) -> bool:
        return bool((getattr(self._cfg, field, "") or "").strip())

    def _is_configured(self, module: str) -> bool:
        field = BREACH_API_KEYS.get(module) or _DISCOVERABLE_VARS.get(module)
        if not field:
            return False
        return bool((getattr(self._cfg, field, "") or "").strip())

    def _set_attr(self, module: str, value: str) -> None:
        """Set a settings attribute for *module* (used during env discovery)."""
        field = BREACH_API_KEYS.get(module) or _DISCOVERABLE_VARS.get(module)
        if field:
            setattr(self._cfg, field, value)

    def sources_summary(self) -> list[dict[str, Any]]:
        """Return a summary of all known sources for the doctor CLI command."""
        rows: list[dict[str, Any]] = []
        all_sources = {**BREACH_API_KEYS, **_DISCOVERABLE_VARS}
        for module, field in sorted(all_sources.items()):
            configured = self._has_key(field)
            healthy = self.health_check(module) if configured else False
            chain = self.fallback_chain(module)
            rows.append(
                {
                    "module": module,
                    "configured": configured,
                    "healthy": healthy,
                    "field": field,
                    "fallbacks": chain,
                }
            )
        return rows
