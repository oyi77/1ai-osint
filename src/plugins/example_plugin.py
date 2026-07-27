"""Example plugin — logs scan start/end events to the console.

This is a minimal working plugin that demonstrates the plugin API.
It registers for the ``on_scan_start`` and ``on_scan_end`` hooks.
"""

from __future__ import annotations

import logging
from typing import Any

from src.plugin.base import BasePlugin

logger = logging.getLogger(__name__)


class ExampleLoggingPlugin(BasePlugin):
    """Plugin that logs scan lifecycle events."""

    name: str = "example_logger"
    version: str = "0.1.0"
    description: str = "Logs scan start/end events to the console"
    hooks: list[str] = ["on_scan_start", "on_scan_end"]

    async def on_scan_start(self, target: str, module: str) -> None:
        logger.info("[ExamplePlugin] Scan started — target=%r module=%r", target, module)
        print(f"[ExamplePlugin] Scan STARTED: target={target!r}, module={module!r}")

    async def on_scan_end(self, result: Any) -> None:
        module_name = getattr(result, "module", "?")
        finding_count = getattr(result, "finding_count", 0)
        logger.info(
            "[ExamplePlugin] Scan ended — module=%r findings=%d",
            module_name,
            finding_count,
        )
        print(
            f"[ExamplePlugin] Scan ENDED: module={module_name!r}, "
            f"findings={finding_count}"
        )


# Module-level instance — discovered by PluginRegistry.discover()
plugin = ExampleLoggingPlugin()
