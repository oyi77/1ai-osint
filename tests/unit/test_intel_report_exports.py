"""Unit tests for intel report exports — JSON, STIX, HTML."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from src.modules.deep_scan import DeepScanResult, Identifier, IdentifierType
from src.modules.deep_scan.models_report import (
    IntelReport,
)
from src.modules.deep_scan.report_generator import generate_intel_report
from src.modules.deep_scan.exports import export_report, export_json, export_stix, export_html


def _sample_report() -> IntelReport:
    """Build a realistic IntelReport for export testing."""
    result = _make_result()
    return generate_intel_report(result)


def _make_result():
    from datetime import timedelta
    from unittest.mock import MagicMock
    now = datetime.now(timezone.utc)
    r = DeepScanResult(
        target="alice",
        started_at=now - timedelta(seconds=1.5),
    )
    r.completed_at = now
    r.iterations = 2
    r.errors = []
    f = MagicMock()
    f.module = "github"
    f.raw_data = {
        "username": "alice",
        "platforms": [
            {"platform": "github", "url": "https://github.com/alice", "status": 200, "exists": True},
            {"platform": "gitlab", "url": "https://gitlab.com/alice", "status": 200, "exists": True},
        ]
    }
    f.title = "alice github"
    f.description = ""
    r.findings = [f]
    r.identifiers = [
        Identifier(value="alice", id_type=IdentifierType.USERNAME, source="github", confidence=0.9),
        Identifier(value="alice@example.com", id_type=IdentifierType.EMAIL, source="leakcheck", confidence=0.8),
    ]
    return r


# --- JSON export ---
class TestJsonExport:
    def test_produces_valid_json(self):
        report = _sample_report()
        result = export_json(report)
        data = json.loads(result)
        assert data["schema_version"] == "1.0.0"
        assert data["target"] == "alice"

    def test_includes_all_sections(self):
        report = _sample_report()
        data = json.loads(export_json(report))
        for key in ("evidence", "risk", "timeline", "identity_graph", "pivots", "confidence_by_identifier"):
            assert key in data, f"Missing key: {key}"

    def test_round_trip_has_consistent_evidence(self):
        report = _sample_report()
        data = json.loads(export_json(report))
        assert len(data["evidence"]) == len(report.evidence)
        assert data["evidence"][0]["identifier_value"] == report.evidence[0].identifier_value

    def test_risk_level_is_string(self):
        report = _sample_report()
        data = json.loads(export_json(report))
        assert isinstance(data["risk"]["level"], str)

    def test_identity_graph_nodes_and_edges(self):
        report = _sample_report()
        data = json.loads(export_json(report))
        graph = data["identity_graph"]
        assert isinstance(graph["nodes"], list)
        assert isinstance(graph["edges"], list)


# --- STIX export ---
class TestStixExport:
    def test_produces_valid_stix_bundle(self):
        report = _sample_report()
        result = export_stix(report)
        data = json.loads(result)
        assert data["type"] == "bundle"
        assert data["spec_version"] == "2.1"
        assert "objects" in data

    def test_includes_identity_sdos(self):
        report = _sample_report()
        data = json.loads(export_stix(report))
        identities = [o for o in data["objects"] if o["type"] == "identity"]
        assert len(identities) > 0
        for ident in identities:
            assert ident["identity_class"] == "individual"

    def test_includes_url_sdos(self):
        report = _sample_report()
        data = json.loads(export_stix(report))
        urls = [o for o in data["objects"] if o["type"] == "url"]
        assert len(urls) > 0
        for url in urls:
            assert url["value"].startswith("http")

    def test_includes_relationship_sdos(self):
        report = _sample_report()
        data = json.loads(export_stix(report))
        rels = [o for o in data["objects"] if o["type"] == "relationship"]
        assert len(rels) > 0

    def test_confidence_mapped_correctly(self):
        report = _sample_report()
        data = json.loads(export_stix(report))
        identities = [o for o in data["objects"] if o["type"] == "identity"]
        # High confidence node should have 85
        high = [i for i in identities if i["confidence"] == 85]
        assert len(high) > 0


# --- HTML export ---
class TestHtmlExport:
    def test_produces_valid_html(self):
        report = _sample_report()
        result = export_html(report)
        assert "<!DOCTYPE html>" in result
        assert "</html>" in result

    def test_has_required_sections(self):
        report = _sample_report()
        result = export_html(report)
        for section in ("Operational Intelligence Brief", "BLUF", "Key judgments", "Digital presence"):
            assert section in result, f"Missing section: {section}"

    def test_contains_evidence_urls(self):
        report = _sample_report()
        result = export_html(report)
        assert "github.com/alice" in result
        assert "gitlab.com/alice" in result

    def test_inline_svg_graph(self):
        report = _sample_report()
        result = export_html(report)
        assert "<svg" in result
        assert "</svg>" in result

    def test_risk_gauge_svg(self):
        report = _sample_report()
        result = export_html(report)
        assert "path" in result  # SVG path for gauge

    def test_no_d3_dependency(self):
        report = _sample_report()
        result = export_html(report)
        assert "d3" not in result.lower()


# --- Export dispatcher ---
class TestExportDispatcher:
    def test_html_format(self):
        report = _sample_report()
        result = export_report(report, fmt="html")
        assert result.startswith("<!DOCTYPE html>")

    def test_json_format(self):
        report = _sample_report()
        result = export_report(report, fmt="json")
        data = json.loads(result)
        assert data["schema_version"] == "1.0.0"

    def test_stix_format(self):
        report = _sample_report()
        result = export_report(report, fmt="stix")
        data = json.loads(result)
        assert data["type"] == "bundle"

    def test_unknown_format_raises(self):
        report = _sample_report()
        with pytest.raises(ValueError, match="Unknown export format"):
            export_report(report, fmt="xml")

    def test_pdf_export(self):
        report = _sample_report()
        pdf = export_report(report, fmt="pdf")
        assert isinstance(pdf, bytes)
        assert len(pdf) > 100
