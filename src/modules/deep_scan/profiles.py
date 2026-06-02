"""Deep scan speed profiles — fast vs full module sets."""
from __future__ import annotations

from src.config import Settings
from src.modules.deep_scan.breach_router import configured_breach_modules

# High-signal, network-light modules (always in fast mode)
FAST_CORE_MODULES: tuple[str, ...] = (
    "social_osint",
    "people_finder",
    "data_leaks",
)

# Skipped in fast mode (heavy subprocess / infra scans)
FAST_SKIP_MODULES: frozenset[str] = frozenset({
    "vuln_scanner",
    "gitleaks",
    "crypto_balance",
    "domain_recon",
})


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
