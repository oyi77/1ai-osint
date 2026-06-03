"""Deep-scan module discovery registry."""

from __future__ import annotations

from src.modules.deep_scan.engine import _MODULE_INPUTS, _SOURCE_MODULES


def list_scan_modules() -> list[str]:
    """Return all registered deep-scan module names."""
    return sorted(_MODULE_INPUTS.keys())


def list_breach_modules() -> list[str]:
    """Return breach/source modules requiring API keys."""
    return sorted(_SOURCE_MODULES)


def module_accepts(module: str, id_type: str) -> bool:
    """Whether module accepts identifier type name (e.g. email, username)."""
    from src.modules.deep_scan import IdentifierType

    try:
        it = IdentifierType(id_type)
    except ValueError:
        return False
    return it in _MODULE_INPUTS.get(module, set())
