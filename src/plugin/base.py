"""Abstract base class for all 1ai-osint plugins."""

from __future__ import annotations

from abc import ABC
from typing import Any


class BasePlugin(ABC):
    """Abstract base class for 1ai-osint plugins.

    Plugins can hook into scan lifecycle events by implementing any of
    the ``on_*`` methods.  Each method has a default no-op implementation
    so subclasses only need to override what they care about.

    Class attributes:
        name:        Short unique plugin name.
        version:     SemVer string.
        description: Human-readable description.
        hooks:       List of hook names this plugin implements (e.g.
                     ``["on_scan_start", "on_scan_end"]``).  Used for
                     fast lookup by the registry.
    """

    name: str = "unnamed"
    version: str = "0.0.0"
    description: str = ""
    hooks: list[str] = []

    # ------------------------------------------------------------------
    # Hook methods – each is a no-op by default
    # ------------------------------------------------------------------

    async def on_scan_start(self, target: str, module: str) -> None:
        """Called when a scan begins.

        Args:
            target: The scan target (URL, email, path, …).
            module: Name of the module performing the scan.
        """
        pass

    async def on_scan_end(self, result: Any) -> None:
        """Called when a scan completes successfully.

        Args:
            result: The ``ScanResult`` (or equivalent) produced by the scan.
        """
        pass

    async def on_report(self, report: Any) -> Any:
        """Called when a report is being generated.

        Plugins may *modify* and return the report, or return it unchanged.

        Args:
            report: The report object (dict, Pydantic model, …).

        Returns:
            The (potentially modified) report.
        """
        return report

    async def on_error(self, error: Exception, context: dict) -> None:
        """Called when a scan or operation encounters an error.

        Args:
            error:   The exception that was raised.
            context: Arbitrary key-value context (module name, target, …).
        """
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}', version='{self.version}')>"
