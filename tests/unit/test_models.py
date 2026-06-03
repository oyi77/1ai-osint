"""Tests for Pydantic models."""

from datetime import datetime
from src.core.models import Finding, ScanResult, BreachRecord, Identity, Severity


class TestFinding:
    def test_create(self):
        f = Finding(id="1", module="test", title="Test")
        assert f.id == "1"
        assert f.severity == Severity.INFO

    def test_severity_values(self):
        for sev in Severity:
            f = Finding(id="1", module="test", title="t", severity=sev)
            assert f.severity == sev


class TestScanResult:
    def test_create(self, sample_finding):
        s = ScanResult(
            scan_id="s1", module="test", target="t", findings=[sample_finding]
        )
        assert s.finding_count == 1
        assert s.status == "ok"

    def test_critical_count(self):
        f = Finding(id="1", module="t", title="t", severity=Severity.CRITICAL)
        s = ScanResult(scan_id="s1", module="t", target="t", findings=[f])
        assert s.critical_count == 1

    def test_duration(self):
        now = datetime.utcnow()
        s = ScanResult(
            scan_id="s1",
            module="t",
            target="t",
            started_at=now,
            completed_at=now,
        )
        assert s.duration_seconds == 0.0

    def test_duration_none_when_not_completed(self):
        s = ScanResult(scan_id="s1", module="t", target="t")
        assert s.duration_seconds is None


class TestBreachRecord:
    def test_create(self):
        b = BreachRecord(source="test", email="a@b.com")
        assert b.source == "test"
        assert b.severity == Severity.MEDIUM


class TestIdentity:
    def test_create(self):
        i = Identity(zkit_hash="abc123")
        assert i.zkit_hash == "abc123"
        assert i.confidence == 1.0
