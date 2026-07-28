"""Pydantic models for entity timeline tracking."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """A single event on an entity's timeline."""

    entity_id: str = Field(..., description="Entity this event relates to")
    event_type: str = Field(..., description="Type of event — scan, finding, risk_change, etc.")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context about the event",
    )
    source: str = Field(default="", description="Module or source that generated the event")


class EntitySnapshot(BaseModel):
    """A point-in-time snapshot of an entity's known state."""

    entity_id: str = Field(..., description="Entity this snapshot belongs to")
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Aggregated attributes known about the entity",
    )
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = Field(default=0, ge=0)

    @property
    def is_empty(self) -> bool:
        """Return True if this snapshot carries no meaningful data."""
        return not self.attributes and self.risk_score == 0.0 and self.event_count == 0


class Timeline(BaseModel):
    """Ordered history of events and snapshots for a single entity."""

    entity_id: str = Field(..., description="Entity being tracked")
    events: list[TimelineEvent] = Field(default_factory=list)
    snapshots: list[EntitySnapshot] = Field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def snapshot_count(self) -> int:
        return len(self.snapshots)

    @property
    def event_types(self) -> Counter:
        """Return a Counter of event types across all events."""
        return Counter(e.event_type for e in self.events)

    @property
    def date_range(self) -> tuple[datetime | None, datetime | None]:
        """Return (earliest, latest) timestamps across all events."""
        if not self.events:
            return None, None
        timestamps = [e.timestamp for e in self.events if e.timestamp]
        if not timestamps:
            return None, None
        return min(timestamps), max(timestamps)
