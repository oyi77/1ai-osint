"""Tests for operational briefing builder."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from src.modules.deep_scan import DeepScanResult, Identifier, IdentifierType
from src.modules.deep_scan.briefing_builder import build_operational_briefing
from src.modules.deep_scan.report_generator import generate_intel_report


def test_briefing_includes_bluf_and_handles():
    now = datetime.now(timezone.utc)
    result = DeepScanResult(target="Fikri Izzuddin", started_at=now)
    result.completed_at = now
    result.identifiers = [
        Identifier(
            value="fikriizzuddin", id_type=IdentifierType.USERNAME, source="pivot"
        ),
    ]
    f = MagicMock()
    f.module = "social_osint"
    f.raw_data = {
        "username": "fikriizzuddin",
        "platforms": [
            {"platform": "github", "status": 404, "exists": False},
            {"platform": "gitlab", "status": 200, "exists": True},
        ],
    }
    f.title = "check"
    f.description = ""
    f.confidence = 0.8
    result.findings = [f]

    report = generate_intel_report(result)
    assert report.briefing.bluf
    assert "fikriizzuddin" in report.briefing.subject.known_handles
    assert len(report.briefing.digital_accounts) >= 1
    assert report.briefing.key_judgments


def test_build_operational_briefing_gaps_when_no_breach():
    now = datetime.now(timezone.utc)
    result = DeepScanResult(target="Test User", started_at=now)
    result.completed_at = now
    report = generate_intel_report(result)
    briefing = build_operational_briefing(result, report)
    assert any("breach" in g.lower() for g in briefing.intelligence_gaps)


def test_briefing_includes_crypto_address():
    now = datetime.now(timezone.utc)
    result = DeepScanResult(target="Test User", started_at=now)
    result.completed_at = now
    result.identifiers = [
        Identifier(
            value="0x1234567890123456789012345678901234567890",
            id_type=IdentifierType.CRYPTO_ADDRESS,
            source="etherscan",
        ),
    ]
    report = generate_intel_report(result)
    briefing = build_operational_briefing(result, report)
    assert (
        "0x1234567890123456789012345678901234567890"
        in briefing.subject.crypto_addresses
    )
