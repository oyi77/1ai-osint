"""Deep scan speed profiles — data-driven, configurable, validated.

Provides the original constants and functions (``FAST_CORE_MODULES``,
``fast_module_list()``, etc.) for backward compatibility alongside the
richer ``ProfilesManager`` class that loads profiles from JSON/YAML
config files, validates them, and allows custom profile building.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.core.config import Settings
from src.modules.deep_scan.breach_router import (
    BREACH_API_KEYS,
    configured_breach_modules,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Backward-compatible constants and functions
# ------------------------------------------------------------------

# High-signal, network-light modules (always in fast mode)
FAST_CORE_MODULES: tuple[str, ...] = (
    "social_osint",
    "people_finder",
    "data_leaks",
)

# Skipped in fast mode (heavy subprocess / infra scans)
FAST_SKIP_MODULES: frozenset[str] = frozenset(
    {
        "vuln_scanner",
        "gitleaks",
        "crypto_balance",
        "crypto_tracer",
        "domain_recon",
    }
)


def breach_modules_with_keys(settings: Settings | None = None) -> list[str]:
    """Breach sources that have API keys in the environment."""
    return configured_breach_modules(settings)


def fast_module_list(settings: Settings | None = None) -> list[str]:
    """Modules for --fast deep scan."""
    return list(FAST_CORE_MODULES) + breach_modules_with_keys(settings)


def fast_scan_defaults() -> dict[str, int | float]:
    return {
        "max_iterations": 2,
        "timeout_per_module": 12.0,
        "max_identifiers": 80,
        "max_pivot_handles": 2,
        "max_targets_per_iteration": 6,
        "max_concurrency": 20,
    }


# ------------------------------------------------------------------
# Default built-in profiles (also the scheme for config files)
# ------------------------------------------------------------------

_BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "fast": {
        "description": "Quick surface scan — social, people, data leaks plus configured breach APIs",
        "modules": list(FAST_CORE_MODULES),
        "settings": fast_scan_defaults(),
    },
    "full": {
        "description": "Full deep scan — all modules, slower, more thorough",
        "modules": [
            "social_osint",
            "people_finder",
            "data_leaks",
            "vuln_scanner",
            "gitleaks",
            "crypto_balance",
            "crypto_tracer",
            "domain_recon",
        ],
        "settings": {
            "max_iterations": 5,
            "timeout_per_module": 30.0,
            "max_identifiers": 200,
            "max_pivot_handles": 10,
            "max_targets_per_iteration": 15,
            "max_concurrency": 40,
        },
    },
    "stealth": {
        "description": "Low-noise scan — no subprocess tools, minimal API calls, longer delays",
        "modules": ["social_osint", "people_finder"],
        "settings": {
            "max_iterations": 1,
            "timeout_per_module": 60.0,
            "max_identifiers": 30,
            "max_pivot_handles": 1,
            "max_targets_per_iteration": 3,
            "max_concurrency": 5,
        },
    },
    "breach_only": {
        "description": "Only breach API lookups — no social, no domain recon",
        "modules": ["data_leaks"],
        "settings": {
            "max_iterations": 1,
            "timeout_per_module": 20.0,
            "max_identifiers": 100,
            "max_pivot_handles": 0,
            "max_targets_per_iteration": 10,
            "max_concurrency": 30,
        },
    },
}


# ------------------------------------------------------------------
# Profile schema for validation
# ------------------------------------------------------------------

_REQUIRED_PROFILE_KEYS: frozenset[str] = frozenset({"description", "modules", "settings"})
_REQUIRED_SETTINGS_KEYS: frozenset[str] = frozenset(
    {
        "max_iterations",
        "timeout_per_module",
        "max_identifiers",
        "max_pivot_handles",
        "max_targets_per_iteration",
        "max_concurrency",
    }
)
_VALID_MODULES: frozenset[str] = frozenset(
    {
        "social_osint",
        "people_finder",
        "data_leaks",
        "vuln_scanner",
        "gitleaks",
        "crypto_balance",
        "crypto_tracer",
        "domain_recon",
    }
)


# ------------------------------------------------------------------
# ProfilesManager
# ------------------------------------------------------------------


class ProfilesManager:
    """Data-driven scan profile manager.

    Compared to the static ``fast_module_list()``, this class:

    * Loads profiles from JSON/YAML config files.
    * Validates profiles against a schema.
    * Allows building custom profiles programmatically.
    * Merges built-in profiles with user-defined ones.
    * Can resolve which modules are active for a given profile + API keys.
    """

    def __init__(self, config_dir: Path | str | None = None):
        root = Path(config_dir) if config_dir else (Settings().project_root / "config" / "profiles")
        self._config_dir = Path(root)
        self._profiles: dict[str, dict[str, Any]] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # load / save
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._profiles = dict(_BUILTIN_PROFILES)  # start with built-ins
        self._load_from_dir()
        self._loaded = True

    def _load_from_dir(self) -> None:
        if not self._config_dir.exists():
            return
        for path in sorted(self._config_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    logger.warning("Skipping non-object profile: %s", path)
                    continue
                for name, profile in data.items():
                    if isinstance(profile, dict):
                        self._profiles[name] = profile
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load profile %s: %s", path, exc)

    def save_profile(self, name: str, profile: dict[str, Any]) -> None:
        """Save a profile to the config directory as JSON."""
        self._ensure_loaded()
        self._config_dir.mkdir(parents=True, exist_ok=True)
        errors = self.validate(profile)
        if errors:
            raise ValueError(f"Invalid profile '{name}': {errors}")

        file_path = self._config_dir / f"{name}.json"
        if file_path.exists():
            existing = json.loads(file_path.read_text(encoding="utf-8"))
            existing[name] = profile
            file_path.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")
        else:
            file_path.write_text(json.dumps({name: profile}, indent=2, default=str), encoding="utf-8")
        self._profiles[name] = profile
        logger.info("Saved profile '%s' to %s", name, file_path)

    # ------------------------------------------------------------------
    # access
    # ------------------------------------------------------------------

    def list_profiles(self) -> dict[str, dict[str, Any]]:
        """Return all available profile definitions."""
        self._ensure_loaded()
        return dict(self._profiles)

    def get_profile(self, name: str) -> dict[str, Any] | None:
        """Return a single profile by name, or None."""
        self._ensure_loaded()
        return self._profiles.get(name)

    def profile_names(self) -> list[str]:
        """Return sorted list of available profile names."""
        self._ensure_loaded()
        return sorted(self._profiles.keys())

    # ------------------------------------------------------------------
    # module resolution
    # ------------------------------------------------------------------

    def resolve_modules(
        self,
        profile_name: str,
        *,
        settings: Settings | None = None,
    ) -> list[str]:
        """Resolve the module list for a given profile, filtering by API key availability.

        Returns only modules that can actually run given the current
        environment (breach modules without keys are excluded).
        """
        self._ensure_loaded()
        profile = self._profiles.get(profile_name)
        if not profile:
            raise KeyError(f"Unknown profile: {profile_name}. Available: {self.profile_names()}")

        modules = list(profile.get("modules", []))
        cfg = settings or Settings()

        # Filter breach modules
        available_breach = set(configured_breach_modules(cfg))
        filtered: list[str] = []
        for mod in modules:
            if mod in BREACH_API_KEYS and mod not in available_breach:
                continue  # skip breach sources without keys
            filtered.append(mod)

        return filtered

    def resolve_settings(self, profile_name: str) -> dict[str, Any]:
        """Return the settings dict for a profile, falling back to fast defaults."""
        self._ensure_loaded()
        profile = self._profiles.get(profile_name)
        if not profile:
            return fast_scan_defaults()
        return profile.get("settings", fast_scan_defaults())

    # ------------------------------------------------------------------
    # custom profile builder
    # ------------------------------------------------------------------

    def build_profile(
        self,
        *,
        name: str,
        description: str,
        modules: list[str],
        max_iterations: int = 3,
        timeout_per_module: float = 15.0,
        max_identifiers: int = 80,
        max_pivot_handles: int = 2,
        max_targets_per_iteration: int = 6,
        max_concurrency: int = 20,
    ) -> dict[str, Any]:
        """Build and save a custom profile programmatically.

        Returns the profile dict on success.
        """
        profile: dict[str, Any] = {
            "description": description,
            "modules": modules,
            "settings": {
                "max_iterations": max_iterations,
                "timeout_per_module": timeout_per_module,
                "max_identifiers": max_identifiers,
                "max_pivot_handles": max_pivot_handles,
                "max_targets_per_iteration": max_targets_per_iteration,
                "max_concurrency": max_concurrency,
            },
        }
        self.save_profile(name, profile)
        return profile

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate(profile: dict[str, Any]) -> list[str]:
        """Validate a profile definition. Returns a list of error messages (empty = valid)."""
        errors: list[str] = []

        missing = _REQUIRED_PROFILE_KEYS - set(profile.keys())
        if missing:
            errors.append(f"Missing required keys: {', '.join(sorted(missing))}")
            return errors  # cannot validate further

        if not isinstance(profile["description"], str) or not profile["description"].strip():
            errors.append("'description' must be a non-empty string")

        modules = profile.get("modules", [])
        if not isinstance(modules, list) or not modules:
            errors.append("'modules' must be a non-empty list")
        else:
            unknown = set(modules) - _VALID_MODULES
            if unknown:
                errors.append(f"Unknown module(s): {', '.join(sorted(unknown))}")

        settings_ = profile.get("settings", {})
        if not isinstance(settings_, dict):
            errors.append("'settings' must be a dict")
        else:
            missing_s = _REQUIRED_SETTINGS_KEYS - set(settings_.keys())
            if missing_s:
                errors.append(f"Settings missing keys: {', '.join(sorted(missing_s))}")
            else:
                for key, expected_type in [
                    ("max_iterations", int),
                    ("timeout_per_module", (int, float)),
                    ("max_identifiers", int),
                    ("max_pivot_handles", int),
                    ("max_targets_per_iteration", int),
                    ("max_concurrency", int),
                ]:
                    val = settings_.get(key)
                    if not isinstance(val, expected_type):  # type: ignore[arg-type]
                        errors.append(f"'{key}' must be {expected_type.__name__}, got {type(val).__name__}")  # type: ignore[attr-defined]

        return errors
