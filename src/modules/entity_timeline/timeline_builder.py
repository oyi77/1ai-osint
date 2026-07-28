"""Deterministic timeline builder — no LLM calls.

Transforms IntelReport / ScanResult objects into ordered entity timelines
and computes entity snapshots and diffs between them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.core.models import ScanResult
from src.modules.deep_scan.models_report import (
    IntelReport,
    RiskLevel,
)

from .models import EntitySnapshot, Timeline, TimelineEvent

# Risk level → numeric score for aggregation
_RISK_ORDER: dict[str, float] = {
    "none": 0.0,
    "info": 0.1,
    "low": 0.3,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}


def _risk_level_to_score(level: RiskLevel | str) -> float:
    """Map a RiskLevel to a float in [0, 1]."""
    if isinstance(level, RiskLevel):
        level = level.value
    return _RISK_ORDER.get(level.lower(), 0.0)


def _pick_timestamp(*candidates: Any) -> datetime:
    """Return the first valid datetime from candidates, or now as fallback."""
    for c in candidates:
        if isinstance(c, datetime):
            return c
    return datetime.now(timezone.utc)


class TimelineBuilder:
    """Build entity timelines from scan results and intel reports.

    All methods are deterministic — no LLM or external API calls.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_timeline(
        self,
        entity_id: str,
        reports: list,  # list[IntelReport | ScanResult]
    ) -> Timeline:
        """Build a complete Timeline from a list of scan results / reports.

        Parameters
        ----------
        entity_id:
            The entity being tracked.
        reports:
            Mix of IntelReport and ScanResult objects in any order.

        Returns
        -------
        Timeline with events sorted chronologically and snapshots
        built from aggregated state.

        """
        events: list[TimelineEvent] = []

        for report in reports:
            if isinstance(report, IntelReport):
                events.extend(self._events_from_intel_report(entity_id, report))
            elif isinstance(report, ScanResult):
                events.extend(self._events_from_scan_result(entity_id, report))
            # Silently skip unknown types.

        # Sort chronologically
        events.sort(key=lambda e: e.timestamp)

        # Build snapshots
        snapshots = self._build_snapshots(entity_id, events)

        return Timeline(entity_id=entity_id, events=events, snapshots=snapshots)

    def diff_snapshots(
        self,
        before: EntitySnapshot,
        after: EntitySnapshot,
    ) -> list[dict]:
        """Compute a list of changes between two snapshots.

        Each change is a dict with keys:
            field  — attribute name
            before — previous value (or None)
            after  — new value (or None)
        """
        changes: list[dict] = []

        # Risk score
        if before.risk_score != after.risk_score:
            changes.append(
                {
                    "field": "risk_score",
                    "before": before.risk_score,
                    "after": after.risk_score,
                }
            )

        # Event count
        if before.event_count != after.event_count:
            changes.append(
                {
                    "field": "event_count",
                    "before": before.event_count,
                    "after": after.event_count,
                }
            )

        # Attributes — added, removed, changed
        before_keys = set(before.attributes.keys())
        after_keys = set(after.attributes.keys())

        added = after_keys - before_keys
        removed = before_keys - after_keys
        common = before_keys & after_keys

        for key in sorted(added):
            changes.append(
                {
                    "field": f"attributes.{key}",
                    "before": None,
                    "after": after.attributes[key],
                }
            )

        for key in sorted(removed):
            changes.append(
                {
                    "field": f"attributes.{key}",
                    "before": before.attributes[key],
                    "after": None,
                }
            )

        for key in sorted(common):
            if before.attributes[key] != after.attributes[key]:
                changes.append(
                    {
                        "field": f"attributes.{key}",
                        "before": before.attributes[key],
                        "after": after.attributes[key],
                    }
                )

        # first_seen / last_seen
        for field in ("first_seen", "last_seen"):
            bv = getattr(before, field, None)
            av = getattr(after, field, None)
            if bv != av:
                changes.append(
                    {
                        "field": field,
                        "before": bv,
                        "after": av,
                    }
                )

        return changes

    # ------------------------------------------------------------------
    # Internal: event extraction
    # ------------------------------------------------------------------

    def _events_from_intel_report(
        self,
        entity_id: str,
        report: IntelReport,
    ) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []

        # 1. Scan-started event
        started = _pick_timestamp(report.started_at)
        events.append(
            TimelineEvent(
                entity_id=entity_id,
                event_type="scan_started",
                timestamp=started,
                context={
                    "report_id": report.report_id,
                    "target": report.target,
                    "modules_run": report.modules_run.copy(),
                },
                source="intel_report",
            )
        )

        # 2. Scan-completed event
        completed = _pick_timestamp(report.completed_at, report.started_at)
        events.append(
            TimelineEvent(
                entity_id=entity_id,
                event_type="scan_completed",
                timestamp=completed,
                context={
                    "report_id": report.report_id,
                    "duration_sec": report.duration_sec,
                    "iterations": report.iterations,
                },
                source="intel_report",
            )
        )

        # 3. Evidence items → "evidence_found"
        for ev in report.evidence:
            ts = _pick_timestamp(ev.captured_at)
            events.append(
                TimelineEvent(
                    entity_id=entity_id,
                    event_type="evidence_found",
                    timestamp=ts,
                    context={
                        "evidence_id": ev.id,
                        "identifier_type": ev.identifier_type,
                        "identifier_value": ev.identifier_value,
                        "source": ev.source,
                        "confidence": ev.confidence,
                    },
                    source=ev.source or "intel_report",
                )
            )

        # 4. Risk assessment → "risk_assessed"
        risk = report.risk
        ts_risk = _pick_timestamp(completed)
        events.append(
            TimelineEvent(
                entity_id=entity_id,
                event_type="risk_assessed",
                timestamp=ts_risk,
                context={
                    "level": risk.level.value if isinstance(risk.level, RiskLevel) else str(risk.level),
                    "score": risk.score,
                    "factor_count": len(risk.factors),
                    "reasoning": risk.reasoning,
                },
                source="intel_report",
            )
        )

        # 5. Existing timeline entries from the report itself
        for entry in report.timeline:
            ts = _pick_timestamp(entry.timestamp)
            events.append(
                TimelineEvent(
                    entity_id=entity_id,
                    event_type="timeline_entry",
                    timestamp=ts,
                    context={
                        "event": entry.event,
                        "detail": entry.detail,
                        "confidence": entry.confidence,
                    },
                    source=entry.source or "intel_report",
                )
            )

        # 6. Module-run events
        for module_name in report.modules_run:
            events.append(
                TimelineEvent(
                    entity_id=entity_id,
                    event_type="module_run",
                    timestamp=completed,
                    context={"module": module_name},
                    source=module_name,
                )
            )

        return events

    def _events_from_scan_result(
        self,
        entity_id: str,
        result: ScanResult,
    ) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []

        started = _pick_timestamp(result.started_at)
        completed = _pick_timestamp(result.completed_at, result.started_at)

        # Scan started
        events.append(
            TimelineEvent(
                entity_id=entity_id,
                event_type="scan_started",
                timestamp=started,
                context={"module": result.module, "target": result.target, "scan_id": result.scan_id},
                source=result.module,
            )
        )

        # Scan completed
        events.append(
            TimelineEvent(
                entity_id=entity_id,
                event_type="scan_completed",
                timestamp=completed,
                context={
                    "module": result.module,
                    "scan_id": result.scan_id,
                    "status": result.status,
                    "finding_count": result.finding_count,
                },
                source=result.module,
            )
        )

        # Findings
        for finding in result.findings:
            ts = _pick_timestamp(finding.timestamp)
            events.append(
                TimelineEvent(
                    entity_id=entity_id,
                    event_type="finding",
                    timestamp=ts,
                    context={
                        "finding_id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value
                        if hasattr(finding.severity, "value")
                        else str(finding.severity),
                        "module": finding.module,
                        "confidence": finding.confidence,
                    },
                    source=finding.module or result.module,
                )
            )

        return events

    # ------------------------------------------------------------------
    # Internal: snapshot building
    # ------------------------------------------------------------------

    def _build_snapshots(
        self,
        entity_id: str,
        events: list[TimelineEvent],
    ) -> list[EntitySnapshot]:
        """Create a snapshot after every event, building cumulative state."""
        snapshots: list[EntitySnapshot] = []
        if not events:
            return snapshots

        # Cumulative aggregation
        cum_attributes: dict[str, Any] = {}
        cum_risk: float = 0.0
        cum_first: datetime | None = events[0].timestamp
        cum_last: datetime | None = events[0].timestamp

        for i, event in enumerate(events):
            # Update cumulative state
            if event.timestamp:
                if cum_first is None or event.timestamp < cum_first:
                    cum_first = event.timestamp
                if cum_last is None or event.timestamp > cum_last:
                    cum_last = event.timestamp

            # Merge context into attributes (simple key depth)
            self._merge_context(cum_attributes, event.context, event.event_type)

            # Update risk from risk_assessed events
            if event.event_type == "risk_assessed":
                cum_risk = event.context.get("score", cum_risk)

            snapshots.append(
                EntitySnapshot(
                    entity_id=entity_id,
                    attributes=cum_attributes.copy(),
                    risk_score=round(cum_risk, 4),
                    first_seen=cum_first,
                    last_seen=cum_last,
                    event_count=i + 1,
                )
            )

        return snapshots

    @staticmethod
    def _merge_context(
        target: dict[str, Any],
        context: dict[str, Any],
        event_type: str,
    ) -> None:
        """Merge event context into a cumulative attribute dict.

        Uses prefixes to avoid key collisions across event types.
        """
        prefix = event_type.replace(" ", "_")
        for k, v in context.items():
            key = f"{prefix}.{k}" if k not in ("modules_run",) else k
            # Don't overwrite existing keys for most fields
            if key not in target:
                target[key] = v
            # But keep the latest for certain fields
            if key in ("source",):
                target[key] = v


# Convenience singleton
BUILDER = TimelineBuilder()
