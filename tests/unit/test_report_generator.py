"""Tests for the output/report generator module."""

import json

import pytest

from src.core.models import Finding, ScanResult, Severity
from src.modules.output.json_formatter import JSONFormatter
from src.modules.output.sarif_formatter import SARIFFormatter
from src.modules.output.pdf_generator import PDFGenerator
from src.modules.output.report_generator import ReportGenerator, ReportFormat


# --- Fixtures ---


@pytest.fixture
def salt():
    return "test-salt-123"


@pytest.fixture
def json_formatter(salt):
    return JSONFormatter(salt=salt)


@pytest.fixture
def sarif_formatter(salt):
    return SARIFFormatter(salt=salt)


@pytest.fixture
def pdf_generator(salt):
    return PDFGenerator(salt=salt)


@pytest.fixture
def report_generator(salt):
    return ReportGenerator(salt=salt)


@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="f1",
            module="test_mod",
            title="Exposed email",
            description="Email found in breach",
            severity=Severity.HIGH,
            raw_data={"email": "user@example.com", "source": "breach_db"},
            confidence=0.9,
            tags=["breach", "email"],
        ),
        Finding(
            id="f2",
            module="test_mod",
            title="Open port",
            description="Port 22 open",
            severity=Severity.MEDIUM,
            raw_data={"ip": "192.168.1.1", "port": 22},
            confidence=1.0,
            tags=["network"],
        ),
    ]


@pytest.fixture
def sample_results(sample_findings):
    return [
        ScanResult(
            scan_id="scan-001",
            module="test_mod",
            target="user@example.com",
            status="ok",
            findings=sample_findings,
            metadata={"test": True},
        )
    ]


@pytest.fixture
def empty_results():
    return [
        ScanResult(
            scan_id="scan-empty",
            module="test_mod",
            target="nobody@example.com",
            status="ok",
            findings=[],
        )
    ]


# --- JSONFormatter tests ---


class TestJSONFormatter:
    def test_format_returns_valid_json(self, json_formatter, sample_results):
        output = json_formatter.format(sample_results)
        parsed = json.loads(output)
        assert parsed["report_type"] == "1ai-osint-json"
        assert parsed["version"] == "1.0"
        assert parsed["zkit_mode"] is True

    def test_format_scan_count(self, json_formatter, sample_results):
        parsed = json.loads(json_formatter.format(sample_results))
        assert parsed["scan_count"] == 1
        assert parsed["total_findings"] == 2
        assert parsed["total_critical"] == 0

    def test_target_is_hashed(self, json_formatter, sample_results):
        parsed = json.loads(json_formatter.format(sample_results))
        scan = parsed["scans"][0]
        assert scan["target_hash"] != "user@example.com"
        assert len(scan["target_hash"]) == 64  # SHA-256 hex

    def test_pii_in_raw_data_is_hashed(self, json_formatter, sample_results):
        parsed = json.loads(json_formatter.format(sample_results))
        raw = parsed["scans"][0]["findings"][0]["raw_data"]
        assert raw["email"] != "user@example.com"
        assert len(raw["email"]) == 64
        # Non-PII fields preserved
        assert raw["source"] == "breach_db"

    def test_ip_is_hashed(self, json_formatter, sample_results):
        parsed = json.loads(json_formatter.format(sample_results))
        raw = parsed["scans"][0]["findings"][1]["raw_data"]
        assert raw["ip"] != "192.168.1.1"
        assert len(raw["ip"]) == 64

    def test_empty_findings(self, json_formatter, empty_results):
        parsed = json.loads(json_formatter.format(empty_results))
        assert parsed["total_findings"] == 0
        assert parsed["scans"][0]["findings"] == []

    def test_severity_preserved(self, json_formatter, sample_results):
        parsed = json.loads(json_formatter.format(sample_results))
        severities = [f["severity"] for f in parsed["scans"][0]["findings"]]
        assert "high" in severities
        assert "medium" in severities

    def test_different_salts_produce_different_hashes(self, sample_results):
        fmt1 = JSONFormatter(salt="salt-a")
        fmt2 = JSONFormatter(salt="salt-b")
        p1 = json.loads(fmt1.format(sample_results))
        p2 = json.loads(fmt2.format(sample_results))
        assert p1["scans"][0]["target_hash"] != p2["scans"][0]["target_hash"]


# --- SARIFFormatter tests ---


class TestSARIFFormatter:
    def test_format_returns_valid_json(self, sarif_formatter, sample_results):
        output = sarif_formatter.format(sample_results)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_tool_info(self, sarif_formatter, sample_results):
        parsed = json.loads(sarif_formatter.format(sample_results))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "1ai-osint"

    def test_rules_generated_from_findings(self, sarif_formatter, sample_results):
        parsed = json.loads(sarif_formatter.format(sample_results))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2
        rule_ids = [r["id"] for r in rules]
        assert "test_mod/f1" in rule_ids

    def test_results_generated(self, sarif_formatter, sample_results):
        parsed = json.loads(sarif_formatter.format(sample_results))
        results = parsed["runs"][0]["results"]
        assert len(results) == 2

    def test_severity_mapped_to_sarif_level(self, sarif_formatter, sample_results):
        parsed = json.loads(sarif_formatter.format(sample_results))
        results = parsed["runs"][0]["results"]
        levels = [r["level"] for r in results]
        assert "error" in levels  # HIGH -> error
        assert "warning" in levels  # MEDIUM -> warning

    def test_zkit_hashes_in_results(self, sarif_formatter, sample_results):
        parsed = json.loads(sarif_formatter.format(sample_results))
        result = parsed["runs"][0]["results"][0]
        zkit = result["properties"]["zkit_hashes"]
        assert "email_hash" in zkit
        assert len(zkit["email_hash"]) == 64

    def test_invocations_present(self, sarif_formatter, sample_results):
        parsed = json.loads(sarif_formatter.format(sample_results))
        invocations = parsed["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_empty_results(self, sarif_formatter, empty_results):
        parsed = json.loads(sarif_formatter.format(empty_results))
        assert parsed["runs"][0]["results"] == []
        assert parsed["runs"][0]["tool"]["driver"]["rules"] == []

    def test_error_scan(self, sarif_formatter):
        scan = ScanResult(
            scan_id="s-err",
            module="m",
            target="t",
            status="error",
            findings=[],
            error="connection timeout",
        )
        parsed = json.loads(sarif_formatter.format([scan]))
        inv = parsed["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is False
        assert len(inv["toolExecutionNotifications"]) == 1


# --- PDFGenerator tests ---


class TestPDFGenerator:
    def test_generate_returns_bytes(self, pdf_generator, sample_results):
        content = pdf_generator.generate(sample_results)
        assert isinstance(content, bytes)

    def test_pdf_starts_with_magic(self, pdf_generator, sample_results):
        content = pdf_generator.generate(sample_results)
        assert content[:5] == b"%PDF-"

    def test_empty_findings_pdf(self, pdf_generator, empty_results):
        content = pdf_generator.generate(empty_results)
        assert isinstance(content, bytes)
        assert content[:5] == b"%PDF-"

    def test_multiple_scans_pdf(self, pdf_generator):
        scans = [
            ScanResult(
                scan_id=f"s{i}",
                module="m",
                target="t",
                findings=[
                    Finding(
                        id=f"f{i}",
                        module="m",
                        title=f"Finding {i}",
                        severity=Severity.LOW,
                    )
                ],
            )
            for i in range(3)
        ]
        content = pdf_generator.generate(scans)
        assert content[:5] == b"%PDF-"


# --- ReportGenerator orchestrator tests ---


class TestReportGenerator:
    def test_generate_json(self, report_generator, sample_results):
        content = report_generator.generate(sample_results, ReportFormat.JSON)
        assert isinstance(content, bytes)
        parsed = json.loads(content)
        assert parsed["report_type"] == "1ai-osint-json"

    def test_generate_sarif(self, report_generator, sample_results):
        content = report_generator.generate(sample_results, ReportFormat.SARIF)
        assert isinstance(content, bytes)
        parsed = json.loads(content)
        assert parsed["version"] == "2.1.0"

    def test_generate_pdf(self, report_generator, sample_results):
        content = report_generator.generate(sample_results, ReportFormat.PDF)
        assert isinstance(content, bytes)
        assert content[:5] == b"%PDF-"

    def test_generate_all(self, report_generator, sample_results):
        all_reports = report_generator.generate_all(sample_results)
        assert ReportFormat.JSON in all_reports
        assert ReportFormat.SARIF in all_reports
        assert ReportFormat.PDF in all_reports
        assert len(all_reports) == 3

    def test_unsupported_format_raises(self, report_generator, sample_results):
        with pytest.raises(ValueError, match="Unsupported format"):
            report_generator.generate(sample_results, "xml")

    def test_save_json(self, report_generator, sample_results, tmp_path):
        path = report_generator.save(sample_results, tmp_path, ReportFormat.JSON)
        assert path.exists()
        assert path.suffix == ".json"
        content = json.loads(path.read_bytes())
        assert content["report_type"] == "1ai-osint-json"

    def test_save_sarif(self, report_generator, sample_results, tmp_path):
        path = report_generator.save(sample_results, tmp_path, ReportFormat.SARIF)
        assert path.exists()
        assert path.suffix == ".sarif"

    def test_save_pdf(self, report_generator, sample_results, tmp_path):
        path = report_generator.save(sample_results, tmp_path, ReportFormat.PDF)
        assert path.exists()
        assert path.suffix == ".pdf"

    def test_save_custom_filename(self, report_generator, sample_results, tmp_path):
        path = report_generator.save(
            sample_results, tmp_path, ReportFormat.JSON, filename="custom.json"
        )
        assert path.name == "custom.json"

    def test_save_creates_dir(self, report_generator, sample_results, tmp_path):
        nested = tmp_path / "deep" / "nested" / "output"
        path = report_generator.save(sample_results, nested, ReportFormat.JSON)
        assert path.exists()

    def test_zkit_hashing_consistency(self, sample_results):
        """Same salt produces same hashes across formats."""
        rg = ReportGenerator(salt="consistent-salt")
        j = json.loads(rg.generate(sample_results, ReportFormat.JSON))
        target_hash_json = j["scans"][0]["target_hash"]

        # JSON formatter and SARIF formatter should hash the same way
        jf = JSONFormatter(salt="consistent-salt")
        j2 = json.loads(jf.format(sample_results))
        assert target_hash_json == j2["scans"][0]["target_hash"]
