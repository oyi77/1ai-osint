"""Tests for models.py uncovered properties and defaults."""
from datetime import datetime, timezone
from src.models import Finding, Severity, ScanResult, BreachRecord, Identity


class TestScanResult:
    def test_finding_count(self):
        r = ScanResult(
            scan_id="t", module="test", target="t", status="ok",
            findings=[
                Finding(id="1", module="m", title="t1", description="d1", severity=Severity.HIGH, confidence=0.9),
                Finding(id="2", module="m", title="t2", description="d2", severity=Severity.LOW, confidence=0.5),
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        assert r.finding_count == 2

    def test_critical_count(self):
        r = ScanResult(
            scan_id="t", module="test", target="t", status="ok",
            findings=[
                Finding(id="1", module="m", title="t1", description="d1", severity=Severity.CRITICAL, confidence=0.9),
                Finding(id="2", module="m", title="t2", description="d2", severity=Severity.LOW, confidence=0.5),
                Finding(id="3", module="m", title="t3", description="d3", severity=Severity.CRITICAL, confidence=0.8),
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        assert r.critical_count == 2

    def test_critical_count_empty(self):
        r = ScanResult(
            scan_id="t", module="test", target="t", status="ok",
            findings=[],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        assert r.critical_count == 0

    def test_duration_seconds(self):
        started = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        completed = datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        r = ScanResult(
            scan_id="t", module="test", target="t", status="ok",
            findings=[], started_at=started, completed_at=completed,
        )
        assert r.duration_seconds == 5.0

    def test_duration_seconds_none(self):
        r = ScanResult(
            scan_id="t", module="test", target="t", status="ok",
            findings=[], started_at=datetime.now(timezone.utc), completed_at=None,
        )
        assert r.duration_seconds is None

    def test_default_status(self):
        r = ScanResult(scan_id="t", module="test", target="t")
        assert r.status == "ok"

    def test_error_field(self):
        r = ScanResult(scan_id="t", module="test", target="t", error="something failed")
        assert r.error == "something failed"


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_from_string(self):
        assert Severity("critical") == Severity.CRITICAL
        assert Severity("high") == Severity.HIGH


class TestFinding:
    def test_defaults(self):
        f = Finding(id="1", module="m", title="t", description="d", severity=Severity.HIGH, confidence=0.9)
        assert f.id == "1"
        assert f.severity == Severity.HIGH
        assert f.confidence == 0.9
        assert f.tags == []
        assert f.raw_data == {}

    def test_default_severity(self):
        f = Finding(id="1", module="m", title="t")
        assert f.severity == Severity.INFO

    def test_default_confidence(self):
        f = Finding(id="1", module="m", title="t")
        assert f.confidence == 0.5


class TestBreachRecord:
    def test_required_source(self):
        b = BreachRecord(source="BreachDB")
        assert b.source == "BreachDB"
        assert b.email is None
        assert b.username is None

    def test_optional_fields(self):
        b = BreachRecord(source="BreachDB", email="test@example.com", domain="example.com")
        assert b.email == "test@example.com"
        assert b.domain == "example.com"


class TestIdentity:
    def test_required_hash(self):
        i = Identity(zkit_hash="abc123")
        assert i.zkit_hash == "abc123"
        assert i.attributes == {}
        assert i.correlation_id is None

    def test_confidence_default(self):
        i = Identity(zkit_hash="abc123")
        assert i.confidence == 1.0
