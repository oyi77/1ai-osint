"""Plugin system for 1ai-osint.

Provides hook-based extensibility for scan lifecycle events.

Typical usage::

    from src.plugin import BasePlugin, PluginRegistry, HookDispatcher

    registry = PluginRegistry()
    registry.discover()
    dispatcher = HookDispatcher(registry)

    # Fire a hook across all interested plugins
    await dispatcher.dispatch("on_scan_start", target="...", module="...")
"""

from __future__ import annotations

from src.plugin.base import BasePlugin
from src.plugin.hooks import HookDispatcher
from src.plugin.registry import PluginRegistry

__all__ = [
    "BasePlugin",
    "HookDispatcher",
    "PluginRegistry",
    "get_dispatcher",
    "reset_plugins",
]

_dispatcher: HookDispatcher | None = None


def get_dispatcher() -> HookDispatcher:
    """Return the process-wide plugin dispatcher (lazy init).

    Discovers plugins once and reuses the registry for the lifetime of the
    process. Safe to call from the engine, the CLI, or the web layer — the
    first caller triggers discovery, everyone else shares the same instance.
    """
    global _dispatcher  # noqa: PLW0603
    if _dispatcher is None:
        registry = PluginRegistry()
        registry.discover()
        _dispatcher = HookDispatcher(registry)
    return _dispatcher


def reset_plugins() -> None:
    """Drop the cached dispatcher (used by tests to force re-discovery)."""
    global _dispatcher  # noqa: PLW0603
    _dispatcher = None
