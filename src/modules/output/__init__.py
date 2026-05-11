"""Report generator base class."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class ReportGenerator(ABC):
    """Base class for all report formatters."""

    @abstractmethod
    def generate(self, findings: list[Dict]) -> bytes:
        """Generate report from findings."""
        ...