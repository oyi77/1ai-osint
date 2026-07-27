"""Tests for the plugin system — base, registry, hooks, and example plugin."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from src.plugin.base import BasePlugin
from src.plugin.hooks import HookDispatcher
from src.plugin.registry import PluginRegistry
from src.plugins.example_plugin import ExampleLoggingPlugin

# ============================================================================
# Helper plugins for testing
# ============================================================================


class NoOpPlugin(BasePlugin):
    """Plugin that does nothing — useful for registration tests."""

    name: str = "noop"
    version: str = "1.0.0"
    description: str = "A no-op test plugin"
    hooks: list[str] = []


class ScanStartPlugin(BasePlugin):
    """Plugin that implements only on_scan_start."""

    name: str = "scan_starter"
    version: str = "0.1.0"
    hooks: list[str] = ["on_scan_start"]

    def __init__(self) -> None:
        super().__init__()
        self.called_with: list[tuple[str, str]] = []

    async def on_scan_start(self, target: str, module: str) -> None:
        self.called_with.append((target, module))


class ScanEndPlugin(BasePlugin):
    """Plugin that implements only on_scan_end."""

    name: str = "scan_ender"
    version: str = "0.2.0"
    hooks: list[str] = ["on_scan_end"]

    def __init__(self) -> None:
        super().__init__()
        self.received: list[Any] = []

    async def on_scan_end(self, result: Any) -> None:
        self.received.append(result)


class MultiHookPlugin(BasePlugin):
    """Plugin that implements both on_scan_start and on_scan_end."""

    name: str = "multi_hook"
    version: str = "1.0.0"
    hooks: list[str] = ["on_scan_start", "on_scan_end"]

    def __init__(self) -> None:
        super().__init__()
        self.starts: list[tuple[str, str]] = []
        self.ends: list[Any] = []

    async def on_scan_start(self, target: str, module: str) -> None:
        self.starts.append((target, module))

    async def on_scan_end(self, result: Any) -> None:
        self.ends.append(result)


class ReportModifierPlugin(BasePlugin):
    """Plugin that transforms on_report output."""

    name: str = "report_modifier"
    version: str = "0.1.0"
    hooks: list[str] = ["on_report"]

    async def on_report(self, report: Any) -> Any:
        if isinstance(report, dict):
            return {**report, "modified": True}
        return report


class FailingPlugin(BasePlugin):
    """Plugin that raises on every hook — tests error isolation."""

    name: str = "failing"
    version: str = "0.0.1"
    hooks: list[str] = ["on_scan_start", "on_scan_end", "on_report"]

    async def on_scan_start(self, target: str, module: str) -> None:
        raise RuntimeError("Start failed!")

    async def on_scan_end(self, result: Any) -> None:
        raise RuntimeError("End failed!")

    async def on_report(self, report: Any) -> Any:
        raise RuntimeError("Report failed!")


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def registry() -> PluginRegistry:
    return PluginRegistry()


@pytest.fixture
def dispatcher(registry: PluginRegistry) -> HookDispatcher:
    return HookDispatcher(registry)


# ============================================================================
# Plugin registration and retrieval
# ============================================================================


class TestPluginRegistration:
    def test_register_and_get(self, registry: PluginRegistry) -> None:
        plugin = NoOpPlugin()
        registry.register(plugin)
        assert registry.get("noop") is plugin

    def test_register_duplicate_raises(self, registry: PluginRegistry) -> None:
        registry.register(NoOpPlugin())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(NoOpPlugin())

    def test_get_missing_raises(self, registry: PluginRegistry) -> None:
        with pytest.raises(KeyError, match="not found"):
            registry.get("non_existent")

    def test_list_empty(self, registry: PluginRegistry) -> None:
        assert registry.list() == []

    def test_list_after_register(self, registry: PluginRegistry) -> None:
        p1 = NoOpPlugin()
        p2 = ScanStartPlugin()
        registry.register(p1)
        registry.register(p2)
        plugins = registry.list()
        assert len(plugins) == 2
        assert p1 in plugins
        assert p2 in plugins

    def test_get_hooks_no_plugins_for_hook(self, registry: PluginRegistry) -> None:
        registry.register(NoOpPlugin())  # has no hooks
        assert registry.get_hooks("on_scan_start") == []

    def test_get_hooks_returns_matching_plugins(self, registry: PluginRegistry) -> None:
        p1 = ScanStartPlugin()
        p2 = MultiHookPlugin()
        p3 = ScanEndPlugin()
        registry.register(p1)
        registry.register(p2)
        registry.register(p3)

        start_hooks = registry.get_hooks("on_scan_start")
        assert len(start_hooks) == 2
        assert p1 in start_hooks
        assert p2 in start_hooks

        end_hooks = registry.get_hooks("on_scan_end")
        assert len(end_hooks) == 2
        assert p2 in end_hooks
        assert p3 in end_hooks


# ============================================================================
# Plugin discovery from directory
# ============================================================================


class TestPluginDiscovery:
    def test_discover_from_package(self, registry: PluginRegistry) -> None:
        """Discover plugins from src.plugins (example_plugin)."""
        discovered = registry.discover(plugins_pkg="src.plugins")
        assert len(discovered) >= 1

        # The example plugin should be one of them
        names = [p.name for p in discovered]
        assert "example_logger" in names

    def test_discover_then_get(self, registry: PluginRegistry) -> None:
        """After discovery we can retrieve by name."""
        registry.discover(plugins_pkg="src.plugins")
        plugin = registry.get("example_logger")
        assert isinstance(plugin, ExampleLoggingPlugin)
        assert plugin.version == "0.1.0"
        assert "on_scan_start" in plugin.hooks
        assert "on_scan_end" in plugin.hooks

    def test_discover_skips_non_plugin_attrs(self, registry: PluginRegistry) -> None:
        """Modules without a 'plugin' attribute are skipped silently."""
        # Should not raise even though src.plugins.__init__ has no `plugin`
        discovered = registry.discover(plugins_pkg="src.plugins")
        # It should find our example plugin
        assert discovered  # at least the example plugin

    def test_discover_from_missing_package(self, registry: PluginRegistry) -> None:
        """A non-existent package returns empty list, no crash."""
        discovered = registry.discover(plugins_pkg="src.plugins.nonexistent")
        assert discovered == []

    @patch("src.plugin.registry.importlib.metadata.entry_points")
    def test_discover_entry_points(self, mock_entry_points, registry: PluginRegistry) -> None:
        """Entry-point based discovery works."""
        mock_ep = MagicMock()
        mock_ep.name = "test_entry_plugin"
        mock_ep.load.return_value = NoOpPlugin
        mock_entry_points.return_value = [mock_ep]

        discovered = registry._discover_from_entry_points()
        assert len(discovered) == 1
        assert discovered[0].name == "noop"


# ============================================================================
# Hook dispatch
# ============================================================================


class TestHookDispatch:
    async def test_dispatch_no_plugins(self, dispatcher: HookDispatcher) -> None:
        results = await dispatcher.dispatch("on_scan_start", target="x", module="y")
        assert results == []

    async def test_dispatch_single_plugin(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        plugin = ScanStartPlugin()
        registry.register(plugin)
        await dispatcher.dispatch("on_scan_start", target="example.com", module="email")
        assert plugin.called_with == [("example.com", "email")]

    async def test_dispatch_multiple_plugins(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        p1 = ScanStartPlugin()
        p2 = MultiHookPlugin()
        registry.register(p1)
        registry.register(p2)

        await dispatcher.dispatch("on_scan_start", target="test", module="domain")
        assert p1.called_with == [("test", "domain")]
        assert p2.starts == [("test", "domain")]

    async def test_dispatch_only_matching_hooks(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        p1 = ScanStartPlugin()  # hooks: on_scan_start
        p2 = ScanEndPlugin()  # hooks: on_scan_end
        registry.register(p1)
        registry.register(p2)

        await dispatcher.dispatch("on_scan_start", target="x", module="y")
        assert len(p1.called_with) == 1
        assert len(p2.received) == 0  # not called

    async def test_on_report_modification(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        modifier = ReportModifierPlugin()
        registry.register(modifier)

        report = {"key": "value"}
        results = await dispatcher.dispatch("on_report", report=report)
        assert len(results) == 1
        assert results[0] == {"key": "value", "modified": True}

    async def test_on_report_transformation_chain(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        """Sequential dispatch where each plugin can modify the report."""

        class ReportModifier2(ReportModifierPlugin):
            name: str = "report_modifier_2"

        registry.register(ReportModifierPlugin())
        registry.register(ReportModifier2())

        results = await dispatcher.dispatch_ordered("on_report", report={"key": "value"})
        assert len(results) == 2
        assert results[0] == {"key": "value", "modified": True}
        assert results[1] == {"key": "value", "modified": True}

    async def test_dispatch_returns_values(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        """dispatch_ordered returns each plugin's return value."""
        p1 = ScanStartPlugin()
        p2 = MultiHookPlugin()
        registry.register(p1)
        registry.register(p2)

        results = await dispatcher.dispatch_ordered("on_scan_start", target="t", module="m")
        # Both return None (the default from the hook signature)
        assert results == [None, None]

    async def test_on_error_hook(self, registry: PluginRegistry, dispatcher: HookDispatcher) -> None:
        """on_error hook receives exception and context dict."""
        received: list[tuple[Exception, dict]] = []

        class ErrorPlugin(BasePlugin):
            name: str = "error_catcher"
            version: str = "0.1.0"
            hooks: list[str] = ["on_error"]

            async def on_error(self, error: Exception, context: dict) -> None:
                received.append((error, context))

        registry.register(ErrorPlugin())
        exc = ValueError("test error")
        ctx = {"module": "test", "target": "x"}
        await dispatcher.dispatch("on_error", error=exc, context=ctx)
        assert len(received) == 1
        assert received[0][0] is exc
        assert received[0][1] == ctx


# ============================================================================
# Error isolation
# ============================================================================


class TestErrorIsolation:
    async def test_failing_plugin_does_not_crash_others(
        self, registry: PluginRegistry, dispatcher: HookDispatcher
    ) -> None:
        good = ScanStartPlugin()
        bad = FailingPlugin()
        registry.register(good)
        registry.register(bad)

        # The failing plugin's error should be swallowed
        await dispatcher.dispatch("on_scan_start", target="safe", module="test")
        assert good.called_with == [("safe", "test")]

    async def test_failing_on_report_returns_good_plugin_results(
        self, registry: PluginRegistry, dispatcher: HookDispatcher
    ) -> None:
        """When one plugin fails on_report, the good one's result is still yielded."""
        good = ReportModifierPlugin()
        bad = FailingPlugin()
        registry.register(good)
        registry.register(bad)

        results = await dispatcher.dispatch("on_report", report={"key": "value"})
        # The good plugin's result should be returned
        assert {"key": "value", "modified": True} in results

    async def test_ordered_dispatch_continues_after_failure(
        self, registry: PluginRegistry, dispatcher: HookDispatcher
    ) -> None:
        """Sequential dispatch continues even if one plugin fails."""

        class GoodScanStartPlugin2(ScanStartPlugin):
            name: str = "scan_starter_good2"

        good1 = ScanStartPlugin()
        bad = FailingPlugin()
        good2 = GoodScanStartPlugin2()
        registry.register(good1)
        registry.register(bad)
        registry.register(good2)

        results = await dispatcher.dispatch_ordered("on_scan_start", target="x", module="y")
        assert len(results) == 2  # Two good results, bad one excluded
        assert results == [None, None]

    async def test_error_logged_not_propagated(
        self, registry: PluginRegistry, dispatcher: HookDispatcher, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The dispatcher logs the plugin error instead of raising."""
        caplog.set_level(logging.ERROR)
        registry.register(FailingPlugin())

        await dispatcher.dispatch("on_scan_start", target="t", module="m")
        assert any("failing" in record.message for record in caplog.records)


# ============================================================================
# Example plugin
# ============================================================================


class TestExamplePlugin:
    def test_example_plugin_instantiation(self) -> None:
        plugin = ExampleLoggingPlugin()
        assert plugin.name == "example_logger"
        assert plugin.version == "0.1.0"
        assert "on_scan_start" in plugin.hooks
        assert "on_scan_end" in plugin.hooks

    def test_example_plugin_module_level_instance(self) -> None:
        """The module-level `plugin` variable is a valid instance."""
        from src.plugins import example_plugin

        assert isinstance(example_plugin.plugin, ExampleLoggingPlugin)
        assert example_plugin.plugin.name == "example_logger"

    @pytest.mark.asyncio
    async def test_example_plugin_on_scan_start(self) -> None:
        plugin = ExampleLoggingPlugin()
        # Should not raise
        await plugin.on_scan_start(target="test@example.com", module="email")

    @pytest.mark.asyncio
    async def test_example_plugin_on_scan_end(self) -> None:
        plugin = ExampleLoggingPlugin()
        result = MagicMock()
        result.module = "test_module"
        type(result).finding_count = PropertyMock(return_value=3)
        await plugin.on_scan_end(result)

    def test_example_plugin_discovered(self) -> None:
        """The example plugin is discovered by the registry."""
        registry = PluginRegistry()
        discovered = registry.discover(plugins_pkg="src.plugins")
        names = [p.name for p in discovered]
        assert "example_logger" in names


# ============================================================================
# CLI integration
# ============================================================================


class TestCLIIntegration:
    def test_plugins_command_exists(self) -> None:
        """The CLI app has a 'plugins' command."""
        from typer.testing import CliRunner

        from src.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["plugins"])
        assert result.exit_code == 0
        assert "Registered plugins" in result.output or "No plugins registered" in result.output

    def test_plugins_command_shows_example_plugin(self) -> None:
        """The plugins command lists example_logger when discovered."""
        from typer.testing import CliRunner

        from src.cli.helpers import init_plugins
        from src.cli.main import app

        # Force discovery
        init_plugins()

        runner = CliRunner()
        result = runner.invoke(app, ["plugins"])
        assert result.exit_code == 0
        assert "example_logger" in result.output
        assert "v0.1.0" in result.output
        assert "on_scan_start" in result.output
        assert "on_scan_end" in result.output
