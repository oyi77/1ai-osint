"""Continuous monitoring — watchlist, change detection, alerting.

Provides persistent watchlist management, structured change-event detection
between intelligence snapshots, and multi-channel alert dispatch.
"""

from __future__ import annotations

from src.modules.monitoring.alerter import (
    AlertDispatcher,
    ConsoleAlerter,
    FileAlerter,
)
from src.modules.monitoring.change_detector import ChangeDetector
from src.modules.monitoring.models import (
    AlertRule,
    ChangeEvent,
    ChangeSeverity,
    ChangeType,
    WatchlistTarget,
)
from src.modules.monitoring.watchlist import WatchlistManager

__all__ = [
    "AlertDispatcher",
    "AlertRule",
    "ChangeDetector",
    "ChangeEvent",
    "ChangeSeverity",
    "ChangeType",
    "ConsoleAlerter",
    "FileAlerter",
    "WatchlistManager",
    "WatchlistTarget",
]
