"""Alert dispatch — route change events to configured channels."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from src.modules.monitoring.models import ChangeEvent

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Channel adapters
# ------------------------------------------------------------------

class BaseAlerter(ABC):
    """Abstract alerter that implements deduplication."""

    def __init__(self, dedup_window_minutes: int = 60):
        self._dedup_window_minutes = dedup_window_minutes
        self._recent_events: dict[str, datetime] = {}

    def _is_duplicate(self, event: ChangeEvent) -> bool:
        """Return True if an identical event was dispatched recently."""
        key = f"{event.target}:{event.change_type.value}:{event.new_value or ''}:{event.old_value or ''}"
        now = datetime.now(timezone.utc)
        # Purge stale entries
        stale_keys = [
            k for k, ts in self._recent_events.items()
            if (now - ts).total_seconds() / 60 > self._dedup_window_minutes
        ]
        for k in stale_keys:
            del self._recent_events[k]

        if key in self._recent_events:
            return True
        self._recent_events[key] = now
        return False

    @abstractmethod
    def _deliver(self, event: ChangeEvent, formatted: str) -> None:
        """Actually send the alert. Implement in subclass."""

    def send(self, event: ChangeEvent) -> bool:
        """Dispatch a single event. Returns True if it was sent (not deduplicated)."""
        if self._is_duplicate(event):
            logger.debug("Deduplicated alert for %s/%s", event.target, event.change_type.value)
            return False
        formatted = self.format_event(event)
        try:
            self._deliver(event, formatted)
            logger.info("Alert sent [%s] %s — %s", event.severity.value, event.target, event.description[:80])
            return True
        except Exception as exc:
            logger.error("Alert delivery failed: %s", exc)
            return False

    @staticmethod
    def format_event(event: ChangeEvent) -> str:
        """Default markdown formatting."""
        lines = [
            f"## Change Event: {event.event_id}",
            f"- **Target:** {event.target}",
            f"- **Type:** {event.change_type.value}",
            f"- **Severity:** {event.severity.value}",
            f"- **Description:** {event.description}",
        ]
        if event.old_value is not None:
            lines.append(f"- **Old value:** `{event.old_value}`")
        if event.new_value is not None:
            lines.append(f"- **New value:** `{event.new_value}`")
        lines.append(f"- **Source:** {event.source_module}")
        lines.append(f"- **Timestamp:** {event.timestamp.isoformat()}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def format_event_json(event: ChangeEvent) -> str:
        """JSON serialisation of the event."""
        return json.dumps(event.model_dump(mode="json"), indent=2, default=str)


class ConsoleAlerter(BaseAlerter):
    """Write alerts to stderr/stdout (always active)."""

    def _deliver(self, event: ChangeEvent, formatted: str) -> None:
        sev = event.severity.value.upper()
        print(f"[ALERT {sev}] {event.target}: {event.description}")


class FileAlerter(BaseAlerter):
    """Append alerts to a rotating log file."""

    def __init__(self, log_dir: Path | str | None = None, dedup_window_minutes: int = 60):
        super().__init__(dedup_window_minutes)
        root = Path(log_dir) if log_dir else Path("investigations") / "watchlist" / "alerts"
        self._log_dir = Path(root)
        self._log_dir.mkdir(parents=True, exist_ok=True)

    def _current_log(self) -> Path:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self._log_dir / f"alerts_{date_str}.jsonl"

    def _deliver(self, event: ChangeEvent, formatted: str) -> None:
        log_path = self._current_log()
        record = {
            "event_id": event.event_id,
            "target": event.target,
            "change_type": event.change_type.value,
            "severity": event.severity.value,
            "description": event.description,
            "old_value": event.old_value,
            "new_value": event.new_value,
            "source_module": event.source_module,
            "timestamp": event.timestamp.isoformat(),
        }
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")


# ------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------

class AlertDispatcher:
    """Route change events to the correct channel adapters."""

    def __init__(self) -> None:
        self._channels: dict[str, BaseAlerter] = {
            "console": ConsoleAlerter(),
        }

    def register_channel(self, name: str, alerter: BaseAlerter) -> None:
        """Register (or replace) a named channel adapter."""
        self._channels[name] = alerter

    def dispatch(
        self,
        change_events: list[ChangeEvent],
        channels: list[str] | None = None,
    ) -> int:
        """Dispatch a batch of events through specified (or all) channels.

        Returns the number of events that were actually sent (post-dedup).
        """
        targets = channels or list(self._channels.keys())
        sent_count = 0
        for event in change_events:
            for ch_name in targets:
                alerter = self._channels.get(ch_name)
                if alerter is None:
                    logger.warning("Unknown alert channel '%s', skipping", ch_name)
                    continue
                if alerter.send(event):
                    sent_count += 1
        return sent_count

    def dispatch_events_markdown(
        self,
        change_events: list[ChangeEvent],
    ) -> str:
        """Render all events as a single markdown report."""
        if not change_events:
            return "No changes detected.\n"
        sections: list[str] = [
            "# Change Detection Report",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Events:** {len(change_events)}",
            "---",
        ]
        for event in change_events:
            sections.append(BaseAlerter.format_event(event))
        return "\n".join(sections)
