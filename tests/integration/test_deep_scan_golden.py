"""Golden-path intel packet (fixture data, no live OSINT)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock


from src.modules.deep_scan import DeepScanResult, Identifier, IdentifierType
from src.modules.deep_scan.exports import export_report
from src.modules.deep_scan.report_generator import generate_intel_report
from src.modules.deep_scan.scan_profiles import resolve_scan_profile


def _fixture_result() -> DeepScanResult:
    now = datetime.now(timezone.utc)
    r = DeepScanResult(target="Fixture Subject", started_at=now - timedelta(seconds=2))
    r.completed_at = now
    r.iterations = 1
    f = MagicMock()
    f.module = "social_osint"
    f.raw_data = {
        "username": "fixture_user",
        "platforms": [
            {
                "platform": "github",
                "url": "https://github.com/fixture_user",
                "status": 200,
                "exists": True,
            },
        ],
    }
    f.title = "fixture_user"
    f.description = ""
    f.confidence = 0.85
    r.findings = [f]
    r.identifiers = [
        Identifier(
            value="fixture_user",
            id_type=IdentifierType.USERNAME,
            source="social_osint",
            confidence=0.9,
        ),
        Identifier(
            value="fixture@example.com",
            id_type=IdentifierType.EMAIL,
            source="data_leaks",
            confidence=0.7,
        ),
    ]
    return r


def test_golden_intel_packet_all_formats():
    prof = resolve_scan_profile("fast")
    assert "social_osint" in prof.modules

    result = _fixture_result()
    intel = generate_intel_report(result)
    html = export_report(intel, fmt="html")
    js = export_report(intel, fmt="json")
    stix = export_report(intel, fmt="stix")
    pdf = export_report(intel, fmt="pdf")

    assert intel.briefing.bluf
    assert "BLUF" in html or "Operational" in html
    payload = json.loads(js)
    assert payload["target"] == "Fixture Subject"
    assert payload.get("briefing")
    bundle = json.loads(stix)
    assert bundle.get("type") == "bundle"
    assert isinstance(pdf, bytes) and len(pdf) > 200


def test_stix_bundle_has_objects():
    intel = generate_intel_report(_fixture_result())
    bundle = json.loads(export_report(intel, fmt="stix"))
    assert "objects" in bundle
    assert len(bundle["objects"]) >= 1
