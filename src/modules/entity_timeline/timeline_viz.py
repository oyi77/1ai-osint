"""Frontend-friendly serialization helpers for entity timelines."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from .models import Timeline, TimelineEvent


def _date_key(dt: datetime | None) -> str:
    """Convert a datetime to 'YYYY-MM-DD' string, or 'unknown'."""
    if dt is None:
        return "unknown"
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d")
    return "unknown"


class TimelineVizData:
    """Transforms a Timeline into JSON-friendly structures for frontend consumption."""

    def __init__(self, timeline: Timeline) -> None:
        self.timeline = timeline

    def to_dict(self) -> dict[str, Any]:
        """Return a fully serializable dict representation."""
        return {
            "entity_id": self.timeline.entity_id,
            "event_count": self.timeline.event_count,
            "snapshot_count": self.timeline.snapshot_count,
            "events": [self._event_to_dict(e) for e in self.timeline.events],
            "snapshots": [
                {
                    "entity_id": s.entity_id,
                    "risk_score": s.risk_score,
                    "first_seen": self._iso(s.first_seen),
                    "last_seen": self._iso(s.last_seen),
                    "event_count": s.event_count,
                    "attributes": s.attributes,
                }
                for s in self.timeline.snapshots
            ],
            "event_types_summary": dict(self.event_types_summary()),
            "events_by_date": self.events_by_date(),
            "date_range": [
                self._iso(self.timeline.date_range[0]),
                self._iso(self.timeline.date_range[1]),
            ],
        }

    def events_by_date(self) -> dict[str, list[dict]]:
        """Return events grouped by 'YYYY-MM-DD' date string."""
        grouped: dict[str, list[dict]] = {}
        for event in self.timeline.events:
            key = _date_key(event.timestamp)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(self._event_to_dict(event))
        return grouped

    def event_types_summary(self) -> Counter:
        """Return a Counter of event types across all events."""
        return self.timeline.event_types

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _event_to_dict(event: TimelineEvent) -> dict[str, Any]:
        return {
            "entity_id": event.entity_id,
            "event_type": event.event_type,
            "timestamp": TimelineVizData._iso(event.timestamp),
            "context": event.context,
            "source": event.source,
        }

    @staticmethod
    def _iso(dt: datetime | None) -> str | None:
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt)
