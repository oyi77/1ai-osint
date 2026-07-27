"""Plugin registry — discover, register, and query plugins."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import pkgutil
from typing import Any

from src.plugin.base import BasePlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Central registry for 1ai-osint plugins.

    Typical usage::

        registry = PluginRegistry()
        registry.discover()               # scan src/plugins/ + entry_points
        registry.register(my_plugin)      # manual registration

        for plugin in registry.get_hooks("on_scan_start"):
            await plugin.on_scan_start(...)
    """

    def __init__(self) -> None:
        self._plugins: dict[str, BasePlugin] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin instance.

        Args:
            plugin: An instance of a ``BasePlugin`` subclass.

        Raises:
            ValueError: If a plugin with the same ``name`` is already
                        registered.
        """
        if plugin.name in self._plugins:
            raise ValueError(
                f"Plugin {plugin.name!r} is already registered "
                f"(version {self._plugins[plugin.name].version})"
            )
        self._plugins[plugin.name] = plugin
        logger.info("Registered plugin %s v%s", plugin.name, plugin.version)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self, plugins_pkg: str = "src.plugins") -> list[BasePlugin]:
        """Discover plugins from two sources:

        1. The ``src.plugins`` package – scans all modules and looks for
           a module-level attribute called ``plugin`` that is a
           ``BasePlugin`` instance.

        2. Package entry points under the ``"1ai_osint.plugins"`` group
           (via ``importlib.metadata``).

        Plugins discovered are automatically registered.

        Args:
            plugins_pkg: Dotted path to the plugins package (default
                         ``src.plugins``).

        Returns:
            List of newly discovered and registered plugin instances.
        """
        discovered: list[BasePlugin] = []

        # 1. Scan the src.plugins package directory
        discovered.extend(self._discover_from_package(plugins_pkg))

        # 2. Scan installed-package entry points
        discovered.extend(self._discover_from_entry_points())

        return discovered

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, name: str) -> BasePlugin:
        """Get a registered plugin by name.

        Raises:
            KeyError: If no plugin with *name* is registered.
        """
        if name not in self._plugins:
            raise KeyError(
                f"Plugin {name!r} not found. "
                f"Registered: {list(self._plugins.keys())}"
            )
        return self._plugins[name]

    def list(self) -> list[BasePlugin]:
        """Return all registered plugin instances."""
        return list(self._plugins.values())

    def get_hooks(self, hook_name: str) -> list[BasePlugin]:
        """Return plugins that implement a specific hook.

        Args:
            hook_name: e.g. ``"on_scan_start"``, ``"on_report"``.

        Returns:
            Plugins whose ``hooks`` list includes *hook_name*.
        """
        return [p for p in self._plugins.values() if hook_name in p.hooks]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_from_package(self, plugins_pkg: str) -> list[BasePlugin]:
        """Scan a package directory for ``plugin`` attributes."""
        discovered: list[BasePlugin] = []

        try:
            pkg = importlib.import_module(plugins_pkg)
        except ImportError:
            logger.debug("Plugins package %s not found, skipping", plugins_pkg)
            return discovered

        # __path__ may be a _NamespacePath, iterate all paths
        pkg_paths = pkg.__path__ if hasattr(pkg, "__path__") else []
        for importer, modname, ispkg in pkgutil.walk_packages(
            pkg_paths, prefix=f"{plugins_pkg}."
        ):
            if ispkg:
                continue
            try:
                mod = importlib.import_module(modname)
            except Exception as exc:
                logger.warning("Failed to import plugin module %s: %s", modname, exc)
                continue

            plugin: Any = getattr(mod, "plugin", None)
            if plugin is None:
                continue
            if not isinstance(plugin, BasePlugin):
                logger.warning(
                    "%s.plugin is not a BasePlugin instance, skipping", modname
                )
                continue

            try:
                self.register(plugin)
                discovered.append(plugin)
            except ValueError:
                # Already registered — still return it as discovered
                discovered.append(self._plugins[plugin.name])

        return discovered

    def _discover_from_entry_points(self) -> list[BasePlugin]:
        """Discover plugins via ``1ai_osint.plugins`` entry points."""
        discovered: list[BasePlugin] = []

        try:
            eps = importlib.metadata.entry_points(group="1ai_osint.plugins")
        except TypeError:
            # Python <3.12 fallback
            all_eps = importlib.metadata.entry_points()
            eps = all_eps.get("1ai_osint.plugins", [])  # type: ignore[union-attr]

        for ep in eps:
            try:
                plugin_cls = ep.load()
            except Exception as exc:
                logger.warning("Failed to load entry point %s: %s", ep.name, exc)
                continue

            if isinstance(plugin_cls, type) and issubclass(plugin_cls, BasePlugin):
                plugin = plugin_cls()
            elif isinstance(plugin_cls, BasePlugin):
                plugin = plugin_cls
            else:
                logger.warning(
                    "Entry point %s does not resolve to a BasePlugin, skipping", ep.name
                )
                continue

            try:
                self.register(plugin)
                discovered.append(plugin)
            except ValueError:
                discovered.append(self._plugins[plugin.name])

        return discovered

    def __repr__(self) -> str:
        count = len(self._plugins)
        return f"<PluginRegistry(plugins={count})>"
