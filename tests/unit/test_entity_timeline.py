"""Unit tests for the entity timeline module.

Tests cover Timeline model construction, TimelineBuilder deterministic
logic, snapshot diff, and timeline_viz serialization.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.core.models import Finding, ScanResult, Severity
from src.modules.deep_scan.models_report import (
    EvidenceItem,
    IntelReport,
    RiskAssessment,
    RiskLevel,
    TimelineEntry,
)
from src.modules.entity_timeline import (
    EntitySnapshot,
    Timeline,
    TimelineBuilder,
    TimelineEvent,
)
from src.modules.entity_timeline.timeline_viz import TimelineVizData

# ======================================================================
# Helpers
# ======================================================================

_BUILDER = TimelineBuilder()

NOW = datetime.now(timezone.utc)
T1 = NOW - timedelta(hours=2)
T2 = NOW - timedelta(hours=1)
T3 = NOW


def _make_finding(
    title: str,
    severity: Severity = Severity.MEDIUM,
    module: str = "test_module",
) -> Finding:
    return Finding(
        id=f"finding_{title[:8]}",
        module=module,
        title=title,
        severity=severity,
        timestamp=T2,
        confidence=0.8,
    )


def _make_scan_result(
    target: str = "test@example.com",
    module: str = "test_module",
    findings: list | None = None,
) -> ScanResult:
    return ScanResult(
        scan_id=f"scan_{module}_{target[:8]}",
        module=module,
        target=target,
        findings=findings or [],
        started_at=T1,
        completed_at=T2,
    )


def _make_evidence(count: int = 2) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            id=f"ev_{i}",
            identifier_type="email" if i == 0 else "username",
            identifier_value=f"test{i}@example.com" if i == 0 else f"user{i}",
            source=f"source_{i}",
            captured_at=T1 + timedelta(minutes=i),
            confidence=0.9,
        )
        for i in range(count)
    ]


def _make_intel_report(
    target: str = "test@example.com",
    module_count: int = 2,
    evidence_count: int = 2,
) -> IntelReport:
    return IntelReport(
        report_id=f"report_{target[:8]}",
        target=target,
        started_at=T1,
        completed_at=T3,
        duration_sec=120.0,
        iterations=3,
        modules_run=[f"module_{i}" for i in range(module_count)],
        evidence=_make_evidence(evidence_count),
        risk=RiskAssessment(
            level=RiskLevel.MEDIUM,
            score=0.65,
            factors=[],  # not needed for event extraction
        ),
        timeline=[
            TimelineEntry(timestamp=T1, source="src_a", event="discovery", detail="Initial find"),
            TimelineEntry(timestamp=T2, source="src_b", event="verification", detail="Confirmed"),
        ],
    )


# ======================================================================
# Timeline model
# ======================================================================


class TestTimelineModel:
    def test_empty_timeline(self):
        t = Timeline(entity_id="nonexistent")
        assert t.event_count == 0
        assert t.snapshot_count == 0
        assert t.date_range == (None, None)
        assert dict(t.event_types) == {}

    def test_event_properties(self):
        t = Timeline(
            entity_id="test",
            events=[
                TimelineEvent(entity_id="test", event_type="scan", timestamp=T1),
                TimelineEvent(entity_id="test", event_type="finding", timestamp=T2),
                TimelineEvent(entity_id="test", event_type="scan", timestamp=T3),
            ],
        )
        assert t.event_count == 3
        assert dict(t.event_types) == {"scan": 2, "finding": 1}
        assert t.date_range == (T1, T3)

    def test_snapshot_is_empty(self):
        s = EntitySnapshot(entity_id="test")
        assert s.is_empty is True

        s2 = EntitySnapshot(entity_id="test", attributes={"key": "val"})
        assert s2.is_empty is False

        s3 = EntitySnapshot(entity_id="test", risk_score=0.5)
        assert s3.is_empty is False

        s4 = EntitySnapshot(entity_id="test", event_count=3)
        assert s4.is_empty is False


# ======================================================================
# TimelineBuilder — build_timeline
# ======================================================================


class TestBuildTimeline:
    def test_empty_reports(self):
        """Empty reports list → empty timeline."""
        t = _BUILDER.build_timeline("entity_x", [])
        assert isinstance(t, Timeline)
        assert t.entity_id == "entity_x"
        assert t.event_count == 0
        assert t.snapshot_count == 0

    def test_single_scan_result(self):
        """Single ScanResult → correct event types and count."""
        findings = [
            _make_finding("Leaked password", Severity.HIGH),
            _make_finding("Email exposure", Severity.MEDIUM),
        ]
        sr = _make_scan_result(findings=findings)
        t = _BUILDER.build_timeline("entity_y", [sr])

        assert t.entity_id == "entity_y"
        assert t.event_count > 0

        types = dict(t.event_types)
        # Should have: scan_started, scan_completed, 2×finding
        assert types.get("scan_started", 0) == 1
        assert types.get("scan_completed", 0) == 1
        assert types.get("finding", 0) == 2

        # Events should be chronological
        timestamps = [e.timestamp for e in t.events]
        assert timestamps == sorted(timestamps)
        assert timestamps[0] == T1  # started_at

    def test_single_intel_report(self):
        """Single IntelReport → events extracted from evidence, risk, timeline."""
        report = _make_intel_report(
            target="person@example.com",
            module_count=3,
            evidence_count=3,
        )
        t = _BUILDER.build_timeline("entity_z", [report])

        assert t.entity_id == "entity_z"
        types = dict(t.event_types)

        # scan_started + scan_completed
        assert types.get("scan_started", 0) == 1
        assert types.get("scan_completed", 0) == 1

        # evidence_found per evidence item
        assert types.get("evidence_found", 0) == 3

        # risk_assessed
        assert types.get("risk_assessed", 0) == 1

        # timeline entries from report.timeline
        assert types.get("timeline_entry", 0) == 2

        # module_run per module
        assert types.get("module_run", 0) == 3

        # Chronological
        timestamps = [e.timestamp for e in t.events]
        assert timestamps == sorted(timestamps)

    def test_multiple_reports_chronological(self):
        """Multiple reports across time produce correctly ordered events."""
        early = _make_scan_result(
            target="multi@test.com",
            findings=[_make_finding("Old finding")],
        )
        late = _make_intel_report(
            target="multi@test.com",
            evidence_count=1,
        )

        # Inject a later timestamp on the intel report so ordering is testable
        late.started_at = T3
        late.completed_at = T3 + timedelta(minutes=5)

        t = _BUILDER.build_timeline("multi", [early, late])
        timestamps = [e.timestamp for e in t.events]
        assert timestamps == sorted(timestamps)

        # First event should be from the early ScanResult
        first_ts = timestamps[0]
        assert first_ts == T1  # early's started_at

        # Last event from the late IntelReport
        last_ts = timestamps[-1]
        assert last_ts > T1

    def test_mixed_report_types(self):
        """Mix of IntelReport and ScanResult is handled gracefully."""
        sr = _make_scan_result(findings=[_make_finding("From scan")])
        ir = _make_intel_report(evidence_count=1)
        t = _BUILDER.build_timeline("mixed", [sr, ir])
        assert t.event_count > 5  # many events from both
        # No unknown-type exceptions
        assert t.entity_id == "mixed"

    def test_unknown_report_type_skipped(self):
        """Objects of unknown type are silently skipped."""
        t = _BUILDER.build_timeline("skip", [1, "string", None, []])

        assert t.event_count == 0  # all skipped

    def test_snapshots_built(self):
        """build_timeline produces one snapshot per event."""
        sr = _make_scan_result(findings=[_make_finding("F1"), _make_finding("F2")])
        t = _BUILDER.build_timeline("snappy", [sr])

        assert len(t.snapshots) == t.event_count
        assert t.snapshots[-1].event_count == t.event_count
        assert t.snapshots[-1].entity_id == "snappy"


# ======================================================================
# TimelineBuilder — diff_snapshots
# ======================================================================


class TestDiffSnapshots:
    def test_no_changes(self):
        before = EntitySnapshot(entity_id="e", attributes={"a": 1}, risk_score=0.5, event_count=5)
        after = EntitySnapshot(entity_id="e", attributes={"a": 1}, risk_score=0.5, event_count=5)
        assert _BUILDER.diff_snapshots(before, after) == []

    def test_risk_change(self):
        before = EntitySnapshot(entity_id="e", risk_score=0.2, event_count=1)
        after = EntitySnapshot(entity_id="e", risk_score=0.8, event_count=2)
        changes = _BUILDER.diff_snapshots(before, after)
        assert {"field": "risk_score", "before": 0.2, "after": 0.8} in changes
        assert {"field": "event_count", "before": 1, "after": 2} in changes

    def test_attribute_added(self):
        before = EntitySnapshot(entity_id="e", attributes={"name": "alice"}, event_count=1)
        after = EntitySnapshot(entity_id="e", attributes={"name": "alice", "email": "a@x.com"}, event_count=2)
        changes = _BUILDER.diff_snapshots(before, after)
        assert {"field": "attributes.email", "before": None, "after": "a@x.com"} in changes

    def test_attribute_removed(self):
        before = EntitySnapshot(entity_id="e", attributes={"name": "alice", "phone": "123"}, event_count=2)
        after = EntitySnapshot(entity_id="e", attributes={"name": "alice"}, event_count=3)
        changes = _BUILDER.diff_snapshots(before, after)
        assert {"field": "attributes.phone", "before": "123", "after": None} in changes

    def test_attribute_changed(self):
        before = EntitySnapshot(entity_id="e", attributes={"score": "low"}, event_count=1)
        after = EntitySnapshot(entity_id="e", attributes={"score": "high"}, event_count=2)
        changes = _BUILDER.diff_snapshots(before, after)
        assert {"field": "attributes.score", "before": "low", "after": "high"} in changes

    def test_seen_dates_change(self):
        now = datetime.now(timezone.utc)
        later = now + timedelta(hours=1)
        before = EntitySnapshot(entity_id="e", first_seen=now, last_seen=now, event_count=1)
        after = EntitySnapshot(entity_id="e", first_seen=now, last_seen=later, event_count=2)
        changes = _BUILDER.diff_snapshots(before, after)
        fields = {c["field"] for c in changes}
        assert "last_seen" in fields
        assert "first_seen" not in fields  # unchanged


# ======================================================================
# TimelineVizData
# ======================================================================


class TestTimelineVizData:
    def test_empty_timeline_viz(self):
        t = Timeline(entity_id="viz_empty")
        viz = TimelineVizData(t)
        d = viz.to_dict()
        assert d["entity_id"] == "viz_empty"
        assert d["event_count"] == 0
        assert d["snapshot_count"] == 0
        assert d["events"] == []
        assert d["events_by_date"] == {}
        assert isinstance(d["date_range"], list)
        assert d["date_range"] == [None, None]

    def test_viz_with_events(self):
        events = [
            TimelineEvent(entity_id="viz", event_type="scan", timestamp=T1, source="mod_a"),
            TimelineEvent(entity_id="viz", event_type="finding", timestamp=T2, source="mod_b"),
            TimelineEvent(entity_id="viz", event_type="scan", timestamp=T3, source="mod_a"),
        ]
        t = Timeline(entity_id="viz", events=events)
        viz = TimelineVizData(t)
        d = viz.to_dict()

        assert d["event_count"] == 3
        assert len(d["events"]) == 3
        # Check serialized format
        evt = d["events"][0]
        assert "entity_id" in evt
        assert "event_type" in evt
        assert "timestamp" in evt
        assert isinstance(evt["timestamp"], str)

        # events_by_date
        by_date = viz.events_by_date()
        assert isinstance(by_date, dict)
        date_key = T1.strftime("%Y-%m-%d")
        assert date_key in by_date
        assert len(by_date[date_key]) >= 1

        # event_types_summary
        summary = viz.event_types_summary()
        assert dict(summary) == {"scan": 2, "finding": 1}

    def test_viz_event_types_summary(self):
        events = [
            TimelineEvent(entity_id="e1", event_type="a"),
            TimelineEvent(entity_id="e1", event_type="b"),
            TimelineEvent(entity_id="e1", event_type="a"),
        ]
        t = Timeline(entity_id="e1", events=events)
        viz = TimelineVizData(t)
        assert dict(viz.event_types_summary()) == {"a": 2, "b": 1}

    def test_viz_events_by_date(self):
        d1 = datetime(2026, 6, 1, tzinfo=timezone.utc)
        d2 = datetime(2026, 6, 2, tzinfo=timezone.utc)
        events = [
            TimelineEvent(entity_id="e", event_type="scan", timestamp=d1),
            TimelineEvent(entity_id="e", event_type="finding", timestamp=d2),
            TimelineEvent(entity_id="e", event_type="scan", timestamp=d1),
        ]
        t = Timeline(entity_id="e", events=events)
        viz = TimelineVizData(t)
        by_date = viz.events_by_date()
        assert "2026-06-01" in by_date
        assert "2026-06-02" in by_date
        assert len(by_date["2026-06-01"]) == 2
        assert len(by_date["2026-06-02"]) == 1


# ======================================================================
# End-to-end: build → snapshot → diff → viz
# ======================================================================


class TestEndToEnd:
    def test_full_pipeline(self):
        """Build timeline from real reports, then serialize through viz."""
        sr1 = _make_scan_result(
            target="pipeline@test.com",
            findings=[_make_finding("Initial leak", Severity.HIGH)],
        )
        sr2 = _make_scan_result(
            target="pipeline@test.com",
            findings=[
                _make_finding("Second leak", Severity.CRITICAL),
                _make_finding("Related account", Severity.LOW),
            ],
        )
        # Force sr2 to be later so ordering is clear
        sr2.started_at = T2
        sr2.completed_at = T3

        t = _BUILDER.build_timeline("pipeline", [sr1, sr2])

        # Verify structure
        assert t.event_count >= 6  # 2×(started+completed) + 3 findings

        # Diff between first and last snapshot
        changes = _BUILDER.diff_snapshots(t.snapshots[0], t.snapshots[-1])
        assert len(changes) > 0

        # Viz
        viz = TimelineVizData(t)
        d = viz.to_dict()
        assert d["entity_id"] == "pipeline"
        assert d["event_count"] == t.event_count
        assert isinstance(d["events_by_date"], dict)
        assert isinstance(d["event_types_summary"], dict)

        # Date range should be populated
        assert d["date_range"][0] is not None
        assert d["date_range"][1] is not None

    def test_mixed_scan_and_intel_report_viz(self):
        """Build timeline from mixed report types and verify viz output."""
        sr = _make_scan_result(findings=[_make_finding("Scan finding")])
        ir = _make_intel_report(evidence_count=1)

        t = _BUILDER.build_timeline("mixed_viz", [sr, ir])
        viz = TimelineVizData(t)
        d = viz.to_dict()

        assert d["entity_id"] == "mixed_viz"
        assert d["event_count"] > 0
        assert "scan_started" in " ".join(e["event_type"] for e in d["events"])
        assert "evidence_found" in " ".join(e["event_type"] for e in d["events"])
