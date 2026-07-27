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
]
