"""Tests for output formatters — JSON, SARIF, PDF."""

import json
from src.core.models import Finding, ScanResult, Severity, Identity, BreachRecord
from src.modules.output.json_formatter import JSONFormatter
from src.modules.output.sarif_formatter import SARIFFormatter
from src.modules.output.sarif import format_sarif
from src.modules.output.pdf_export import format_pdf
from src.modules.output.pdf_generator import PDFGenerator


def _make_scan_result(findings=None, breach_records=None, identities=None):
    return ScanResult(
        scan_id="test-scan-1",
        module="test_module",
        target="test@example.com",
        findings=findings or [],
        breach_records=breach_records or [],
        identities=identities or [],
    )


def _make_finding(severity=Severity.HIGH, raw_data=None):
    return Finding(
        id="f-001",
        module="test_module",
        title="Test Finding",
        description="A test finding",
        severity=severity,
        confidence=0.8,
        tags=["test"],
        raw_data=raw_data or {"email": "test@example.com", "username": "testuser"},
    )


class TestJSONFormatter:
    def test_format_empty_results(self):
        formatter = JSONFormatter(salt="test-salt")
        result = json.loads(formatter.format([]))
        assert result["report_type"] == "1ai-osint-json"
        assert result["scan_count"] == 0
        assert result["zkit_mode"] is True

    def test_format_with_findings(self):
        finding = _make_finding()
        scan = _make_scan_result(findings=[finding])
        formatter = JSONFormatter(salt="salt123")
        result = json.loads(formatter.format([scan]))
        assert result["scan_count"] == 1
        assert result["total_findings"] == 1
        assert result["total_critical"] == 0
        scan_data = result["scans"][0]
        assert scan_data["target_hash"] != "test@example.com"
        assert len(scan_data["target_hash"]) == 64

    def test_hash_value(self):
        formatter = JSONFormatter(salt="my-salt")
        h1 = formatter._hash_value("test@example.com")
        h2 = formatter._hash_value("test@example.com")
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_dict_values(self):
        formatter = JSONFormatter(salt="salt")
        data = {"email": "a@b.com", "name": "Alice", "count": 5}
        hashed = formatter._hash_dict_values(data, {"email"})
        assert hashed["email"] != "a@b.com"
        assert hashed["name"] == "Alice"
        assert hashed["count"] == 5

    def test_format_with_breach_records(self):
        br = BreachRecord(source="hibp", email="a@b.com", severity=Severity.HIGH)
        scan = _make_scan_result(breach_records=[br])
        formatter = JSONFormatter(salt="salt")
        result = json.loads(formatter.format([scan]))
        assert len(result["scans"][0]["breach_records"]) == 1

    def test_format_with_identities(self):
        ident = Identity(zkit_hash="abc123", sources=["test"])
        scan = _make_scan_result(identities=[ident])
        formatter = JSONFormatter(salt="salt")
        result = json.loads(formatter.format([scan]))
        assert len(result["scans"][0]["identities"]) == 1


class TestSARIFFormatter:
    def test_format_empty(self):
        formatter = SARIFFormatter(salt="salt")
        result = json.loads(formatter.format([]))
        assert result["version"] == "2.1.0"
        assert len(result["runs"]) == 1

    def test_format_with_findings(self):
        finding = _make_finding()
        scan = _make_scan_result(findings=[finding])
        formatter = SARIFFormatter(salt="salt")
        result = json.loads(formatter.format([scan]))
        run = result["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1
        assert run["properties"]["zkit_mode"] is True

    def test_severity_mapping(self):
        formatter = SARIFFormatter()
        for sev in Severity:
            level = formatter._severity_to_level(sev)
            assert level in ("error", "warning", "note", "none")

    def test_finding_to_result_with_pii(self):
        finding = _make_finding(raw_data={"email": "a@b.com", "ip": "1.2.3.4"})
        formatter = SARIFFormatter(salt="salt")
        result = formatter._finding_to_result(finding)
        assert "zkit_hashes" in result["properties"]
        assert "email_hash" in result["properties"]["zkit_hashes"]

    def test_scan_to_invocations_with_error(self):
        scan = _make_scan_result()
        scan.error = "Something failed"
        scan.status = "error"
        formatter = SARIFFormatter()
        inv = formatter._scan_to_invocations(scan)
        assert inv["executionSuccessful"] is False
        assert len(inv["toolExecutionNotifications"]) == 1


class TestFormatSarif:
    def test_format_sarif_function(self):
        finding = _make_finding()
        scan = _make_scan_result(findings=[finding])
        result = json.loads(format_sarif([scan]))
        assert result["version"] == "2.1.0"
        assert len(result["runs"][0]["results"]) == 1


class TestPDFExport:
    def test_format_pdf(self):
        finding = _make_finding()
        scan = _make_scan_result(findings=[finding])
        pdf_bytes = format_pdf([scan])
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:4] == b"%PDF"

    def test_format_pdf_no_findings(self):
        scan = _make_scan_result()
        pdf_bytes = format_pdf([scan])
        assert pdf_bytes[:4] == b"%PDF"


class TestPDFGenerator:
    def test_generate(self):
        finding = _make_finding()
        scan = _make_scan_result(findings=[finding])
        gen = PDFGenerator(salt="salt")
        pdf_bytes = gen.generate([scan])
        assert pdf_bytes[:4] == b"%PDF"

    def test_severity_counts(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.LOW),
        ]
        scan = _make_scan_result(findings=findings)
        gen = PDFGenerator()
        counts = gen._severity_counts([scan])
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["low"] == 1

    def test_hash_value(self):
        gen = PDFGenerator(salt="salt")
        h = gen._hash_value("test")
        assert len(h) == 64
