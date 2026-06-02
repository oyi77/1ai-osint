"""Deep scan collection profiles — fast through agency-grade."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from src.config import Settings
from src.modules.deep_scan.profiles import (
    FAST_CORE_MODULES,
    breach_modules_with_keys,
)

ProfileName = Literal["fast", "standard", "deep", "agency"]

STANDARD_EXTRA: tuple[str, ...] = ("email_osint", "phone_finder")
DEEP_EXTRA: tuple[str, ...] = ("domain_recon", "gitleaks")
AGENCY_EXTRA: tuple[str, ...] = ("email_osint", "phone_finder", "domain_recon", "intelx")


@dataclass(frozen=True)
class ScanProfileConfig:
    name: ProfileName
    modules: tuple[str, ...]
    max_iterations: int
    timeout_per_module: float
    max_identifiers: int
    max_pivot_handles: int
    max_targets_per_iteration: int
    max_concurrency: int
    fast_mode: bool


def resolve_scan_profile(
    name: str,
    settings: Settings | None = None,
) -> ScanProfileConfig:
    """Resolve CLI --profile to engine parameters."""
    cfg = settings or Settings()
    keyed_breach = breach_modules_with_keys(cfg)
    n = name.strip().lower()

    if n == "fast":
        return ScanProfileConfig(
            name="fast",
            modules=tuple(list(FAST_CORE_MODULES) + keyed_breach),
            max_iterations=2,
            timeout_per_module=12.0,
            max_identifiers=80,
            max_pivot_handles=2,
            max_targets_per_iteration=6,
            max_concurrency=20,
            fast_mode=True,
        )

    if n == "standard":
        mods = list(FAST_CORE_MODULES) + list(STANDARD_EXTRA) + keyed_breach
        return ScanProfileConfig(
            name="standard",
            modules=tuple(dict.fromkeys(mods)),
            max_iterations=3,
            timeout_per_module=25.0,
            max_identifiers=150,
            max_pivot_handles=3,
            max_targets_per_iteration=10,
            max_concurrency=24,
            fast_mode=False,
        )

    if n == "deep":
        mods = (
            list(FAST_CORE_MODULES)
            + list(STANDARD_EXTRA)
            + list(DEEP_EXTRA)
            + keyed_breach
        )
        return ScanProfileConfig(
            name="deep",
            modules=tuple(dict.fromkeys(mods)),
            max_iterations=5,
            timeout_per_module=40.0,
            max_identifiers=300,
            max_pivot_handles=4,
            max_targets_per_iteration=15,
            max_concurrency=28,
            fast_mode=False,
        )

    if n == "agency":
        mods = list(dict.fromkeys(
            list(FAST_CORE_MODULES) + list(AGENCY_EXTRA) + list(DEEP_EXTRA) + keyed_breach
        ))
        return ScanProfileConfig(
            name="agency",
            modules=tuple(mods),
            max_iterations=8,
            timeout_per_module=60.0,
            max_identifiers=500,
            max_pivot_handles=6,
            max_targets_per_iteration=20,
            max_concurrency=32,
            fast_mode=False,
        )

    raise ValueError(f"Unknown profile '{name}'. Use: fast, standard, deep, agency")
