"""Tests for ZKIT privacy-preserving report formatter."""

import json

import pytest

from src.core.models import BreachRecord, Finding, Identity, ScanResult, Severity
from src.modules.identity_tracking.zkit_engine import (
    CorrelatedCluster,
    CorrelationConfidence,
)
from src.modules.output.zkit_formatter import (
    ZKITFormatter,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def salt() -> str:
    return "test-zkit-formatter-salt"


@pytest.fixture
def formatter(salt: str) -> ZKITFormatter:
    return ZKITFormatter(salt=salt)


@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="f1",
            module="data_leaks",
            title="Exposed email",
            description="Email found in breach",
            severity=Severity.HIGH,
            raw_data={"email": "user@example.com", "source": "breach_db"},
            confidence=0.9,
            tags=["breach", "email"],
        ),
        Finding(
            id="f2",
            module="phone_finder",
            title="Phone linked to email",
            description="Phone found",
            severity=Severity.MEDIUM,
            raw_data={"phone": "+15551234567", "email": "user@example.com"},
            confidence=0.8,
        ),
    ]


@pytest.fixture
def sample_breach_records():
    return [
        BreachRecord(
            source="breach_db",
            email="user@example.com",
            username="testuser",
            domain="example.com",
            ip_address="192.168.1.1",
            severity=Severity.HIGH,
            data_classes=["email", "password"],
        ),
    ]


@pytest.fixture
def sample_results(sample_findings, sample_breach_records):
    return [
        ScanResult(
            scan_id="scan-001",
            module="data_leaks",
            target="user@example.com",
            status="ok",
            findings=sample_findings,
            breach_records=sample_breach_records,
            metadata={"test": True},
        ),
    ]


@pytest.fixture
def empty_results():
    return [
        ScanResult(
            scan_id="scan-empty",
            module="test",
            target="nobody@example.com",
            status="ok",
            findings=[],
        ),
    ]


@pytest.fixture
def sample_clusters():
    return [
        CorrelatedCluster(
            cluster_id="cluster-0000",
            hash_members=["hash_a" + "0" * 57, "hash_b" + "0" * 57],
            attribute_types={"email_hash", "username_hash"},
            score=0.85,
            confidence=CorrelationConfidence.HIGH,
            edge_count=2,
            total_co_occurrences=5,
            sources=["data_leaks", "people_finder"],
        ),
    ]


# ---------------------------------------------------------------------------
# Test ZKITFormatter basic formatting
# ---------------------------------------------------------------------------


class TestZKITFormatterBasic:
    def test_format_returns_valid_json(self, formatter, sample_results):
        output = formatter.format(sample_results)
        parsed = json.loads(output)
        assert parsed["report_type"] == "1ai-osint-zkit"
        assert parsed["zkit_mode"] is True
        assert parsed["privacy_mode"] == "full"

    def test_format_version(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        assert parsed["version"] == "1.0"

    def test_format_scan_count(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        assert parsed["scan_count"] == 1
        assert parsed["total_findings"] == 2

    def test_target_is_hashed(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        scan = parsed["scans"][0]
        assert scan["target_hash"] != "user@example.com"
        assert len(scan["target_hash"]) == 64

    def test_email_in_raw_data_is_hashed(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        raw = parsed["scans"][0]["findings"][0]["raw_data"]
        assert raw["email"] != "user@example.com"
        assert len(raw["email"]) == 64

    def test_phone_is_hashed(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        raw = parsed["scans"][0]["findings"][1]["raw_data"]
        assert raw["phone"] != "+15551234567"
        assert len(raw["phone"]) == 64

    def test_non_pii_fields_preserved(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        raw = parsed["scans"][0]["findings"][0]["raw_data"]
        assert raw["source"] == "breach_db"

    def test_severity_preserved(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        severities = [f["severity"] for f in parsed["scans"][0]["findings"]]
        assert "high" in severities
        assert "medium" in severities

    def test_empty_findings(self, formatter, empty_results):
        parsed = json.loads(formatter.format(empty_results))
        assert parsed["total_findings"] == 0
        assert parsed["scans"][0]["findings"] == []


# ---------------------------------------------------------------------------
# Test breach record formatting
# ---------------------------------------------------------------------------


class TestBreachRecordFormatting:
    def test_email_hashed_in_breach(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        breach = parsed["scans"][0]["breach_records"][0]
        assert "email_hash" in breach
        assert breach["email_hash"] != "user@example.com"
        assert len(breach["email_hash"]) == 64

    def test_username_hashed_in_breach(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        breach = parsed["scans"][0]["breach_records"][0]
        assert "username_hash" in breach
        assert len(breach["username_hash"]) == 64

    def test_domain_hashed_in_breach(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        breach = parsed["scans"][0]["breach_records"][0]
        assert "domain_hash" in breach
        assert len(breach["domain_hash"]) == 64

    def test_ip_hashed_in_breach(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        breach = parsed["scans"][0]["breach_records"][0]
        assert "ip_hash" in breach
        assert breach["ip_hash"] != "192.168.1.1"

    def test_data_classes_preserved(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        breach = parsed["scans"][0]["breach_records"][0]
        assert breach["data_classes"] == ["email", "password"]


# ---------------------------------------------------------------------------
# Test redaction audit
# ---------------------------------------------------------------------------


class TestRedactionAudit:
    def test_audit_tracks_redactions(self, formatter, sample_results):
        formatter.format(sample_results)
        audit = formatter.get_audit()
        assert audit.total_redactions > 0

    def test_audit_tracks_field_names(self, formatter, sample_results):
        formatter.format(sample_results)
        audit = formatter.get_audit()
        assert "email" in audit.pii_fields_redacted
        assert "phone" in audit.pii_fields_redacted

    def test_audit_included_in_output(self, formatter, sample_results):
        parsed = json.loads(formatter.format(sample_results))
        assert "redaction_audit" in parsed
        audit = parsed["redaction_audit"]
        assert audit["total_redactions"] > 0
        assert "email" in audit["pii_fields_redacted"]

    def test_audit_entries_have_source(self, formatter, sample_results):
        formatter.format(sample_results)
        audit = formatter.get_audit()
        for entry in audit.entries:
            assert entry.source_module  # should be non-empty

    def test_audit_reset(self, formatter, sample_results):
        formatter.format(sample_results)
        assert formatter.get_audit().total_redactions > 0
        formatter.reset_audit()
        assert formatter.get_audit().total_redactions == 0

    def test_audit_to_dict(self, formatter, sample_results):
        formatter.format(sample_results)
        audit_dict = formatter.get_audit().to_dict()
        assert "total_redactions" in audit_dict
        assert "pii_fields_redacted" in audit_dict
        assert "entries" in audit_dict


# ---------------------------------------------------------------------------
# Test format_with_clusters
# ---------------------------------------------------------------------------


class TestFormatWithClusters:
    def test_format_with_clusters_returns_json(self, formatter, sample_results, sample_clusters):
        output = formatter.format_with_clusters(sample_results, sample_clusters, investigation_id="inv-001")
        parsed = json.loads(output)
        assert parsed["report_type"] == "1ai-osint-zkit-correlated"
        assert parsed["investigation_id"] == "inv-001"

    def test_clusters_in_output(self, formatter, sample_results, sample_clusters):
        parsed = json.loads(formatter.format_with_clusters(sample_results, sample_clusters))
        clusters = parsed["correlation_clusters"]
        assert len(clusters) == 1
        assert clusters[0]["cluster_id"] == "cluster-0000"
        assert clusters[0]["score"] == 0.85
        assert clusters[0]["confidence"] == "high"

    def test_cluster_no_raw_pii(self, formatter, sample_results, sample_clusters):
        output = formatter.format_with_clusters(sample_results, sample_clusters)
        assert "user@example.com" not in output

    def test_clusters_sorted_attribute_types(self, formatter, sample_results, sample_clusters):
        parsed = json.loads(formatter.format_with_clusters(sample_results, sample_clusters))
        cluster = parsed["correlation_clusters"][0]
        assert cluster["attribute_types"] == sorted(cluster["attribute_types"])

    def test_audit_present_with_clusters(self, formatter, sample_results, sample_clusters):
        parsed = json.loads(formatter.format_with_clusters(sample_results, sample_clusters))
        assert "redaction_audit" in parsed
        assert parsed["redaction_audit"]["total_redactions"] > 0


# ---------------------------------------------------------------------------
# Test PII verification
# ---------------------------------------------------------------------------


class TestVerifyNoPII:
    def test_clean_report_passes(self, formatter, sample_results):
        report = formatter.format(sample_results)
        violations = formatter.verify_no_pii(report)
        assert violations == []

    def test_invalid_json_detected(self, formatter):
        violations = formatter.verify_no_pii("not json {{{")
        assert "invalid_json" in violations

    def test_detects_raw_email_as_value(self, formatter):
        """A dict with key 'email' containing a non-hash value is flagged."""
        bad_data = {"email": "raw@example.com"}
        report = json.dumps(bad_data)
        violations = formatter.verify_no_pii(report)
        assert "email" in violations

    def test_valid_hash_passes(self, formatter):
        """A 64-char hex string in a PII field should pass."""
        good_data = {"email": "a" * 64}
        report = json.dumps(good_data)
        violations = formatter.verify_no_pii(report)
        assert violations == []

    def test_nested_pii_detected(self, formatter):
        bad_data = {"scans": [{"raw_data": {"phone": "not-a-hash"}}]}
        report = json.dumps(bad_data)
        violations = formatter.verify_no_pii(report)
        assert any("phone" in v for v in violations)

    def test_hash_suffix_field_validated(self, formatter):
        """Fields ending in _hash should also be 64-char hex."""
        bad_data = {"email_hash": "short"}
        report = json.dumps(bad_data)
        violations = formatter.verify_no_pii(report)
        assert "email_hash" in violations


# ---------------------------------------------------------------------------
# Test salt consistency
# ---------------------------------------------------------------------------


class TestSaltConsistency:
    def test_same_salt_same_hashes(self, sample_results):
        f1 = ZKITFormatter(salt="consistent-salt")
        f2 = ZKITFormatter(salt="consistent-salt")
        p1 = json.loads(f1.format(sample_results))
        p2 = json.loads(f2.format(sample_results))
        assert p1["scans"][0]["target_hash"] == p2["scans"][0]["target_hash"]

    def test_different_salt_different_hashes(self, sample_results):
        f1 = ZKITFormatter(salt="salt-a")
        f2 = ZKITFormatter(salt="salt-b")
        p1 = json.loads(f1.format(sample_results))
        p2 = json.loads(f2.format(sample_results))
        assert p1["scans"][0]["target_hash"] != p2["scans"][0]["target_hash"]


# ---------------------------------------------------------------------------
# Test identity formatting
# ---------------------------------------------------------------------------


class TestIdentityFormatting:
    def test_identity_already_hashed(self):
        """Identities from ScanResult are already ZKIT-hashed."""
        identity = Identity(
            zkit_hash="a" * 64,
            correlation_id="corr-001",
            sources=["module_a"],
            confidence=0.9,
        )
        result = ScanResult(
            scan_id="s1",
            module="m",
            target="t",
            findings=[],
            identities=[identity],
        )
        formatter = ZKITFormatter(salt="test")
        parsed = json.loads(formatter.format([result]))
        ident = parsed["scans"][0]["identities"][0]
        assert ident["zkit_hash"] == "a" * 64
        assert ident["correlation_id"] == "corr-001"
