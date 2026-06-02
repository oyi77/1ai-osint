"""Breach source router — keyed APIs only, shared by deep scan."""
from __future__ import annotations

from src.config import Settings

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


def breach_status_report(settings: Settings | None = None) -> list[tuple[str, bool, str]]:
    """For doctor: (module, configured, env_var)."""
    cfg = settings or Settings()
    return [
        (mod, bool((getattr(cfg, field, "") or "").strip()), field.upper())
        for mod, field in BREACH_API_KEYS.items()
    ]
