"""Tests for Phase 5 Pillar 1: Adversarial AI Analyst."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.deep_scan.ai_analyst import AdversarialAnalyst, CIAAnalysis


def _make_mock_report(risk_score=0.5, risk_level="medium", evidence_count=10, modules_run=None):
    report = MagicMock()
    report.target = "test@example.com"
    risk = MagicMock()
    risk.score = risk_score
    risk.level = risk_level
    report.risk = risk
    report.modules_run = modules_run or ["social_osint", "email_osint"]
    evidence = []
    for i in range(evidence_count):
        ev = MagicMock()
        ev.source = "social_osint" if i % 2 == 0 else "email_osint"
        ev.identifier_type = "email" if i < 3 else "username"
        evidence.append(ev)
    report.evidence = evidence
    return report


@pytest.mark.asyncio
async def test_deterministic_analysis_low_risk():
    analyst = AdversarialAnalyst()
    report = _make_mock_report(risk_score=0.1, risk_level="low", evidence_count=3)
    with patch.object(analyst, "_llm_available", False):
        result = await analyst.run_analysis(report)
    assert isinstance(result, CIAAnalysis)
    assert result.analytical_method == "deterministic"
    assert "BLUE TEAM" in result.blue_team_narrative
    assert "RED TEAM" in result.red_team_narrative
    assert len(result.intelligence_gaps) > 0
    assert "identity_confirmed" in result.calibrated_confidences


@pytest.mark.asyncio
async def test_deterministic_analysis_high_risk():
    analyst = AdversarialAnalyst()
    report = _make_mock_report(risk_score=0.9, risk_level="critical", evidence_count=50)
    with patch.object(analyst, "_llm_available", False):
        result = await analyst.run_analysis(report)
    assert "HIGH risk score" in result.red_team_narrative
    assert result.calibrated_confidences["adversarial_hypothesis"] >= 0.5


@pytest.mark.asyncio
async def test_bluf_plus_populated():
    analyst = AdversarialAnalyst()
    report = _make_mock_report(risk_score=0.4, risk_level="medium")
    with patch.object(analyst, "_llm_available", False):
        result = await analyst.run_analysis(report)
    assert result.bluf_plus != ""
    assert "SUBJECT" in result.bluf_plus
    assert "RISK" in result.bluf_plus


@pytest.mark.asyncio
async def test_llm_fallback_on_error():
    """LLM errors should fall back to deterministic gracefully."""
    analyst = AdversarialAnalyst()
    report = _make_mock_report()
    with (
        patch.object(analyst, "_llm_available", True),
        patch.object(analyst, "_llm_analysis", new=AsyncMock(side_effect=Exception("API error"))),
    ):
        result = await analyst.run_analysis(report)
    assert isinstance(result, CIAAnalysis)
    assert result.analytical_method == "deterministic"


@pytest.mark.asyncio
async def test_gap_assessment_returns_list():
    analyst = AdversarialAnalyst()
    report = _make_mock_report(modules_run=["social_osint"])
    with patch.object(analyst, "_llm_available", False):
        gaps = await analyst.gap_assessment(report)
    assert isinstance(gaps, list)
    assert len(gaps) >= 1


def test_calibrate_confidence_synchronous():
    analyst = AdversarialAnalyst()
    report = _make_mock_report(risk_score=0.6, evidence_count=20)
    confidences = analyst.calibrate_confidence(report)
    assert 0.0 <= confidences["identity_confirmed"] <= 1.0
    assert 0.0 <= confidences["adversarial_hypothesis"] <= 1.0
    assert confidences["data_currency"] == 0.7


@pytest.mark.asyncio
async def test_check_llm_not_available_without_keys():
    """Without API keys, LLM should not be available."""
    import os

    keys_backup = {k: os.environ.pop(k, None) for k in ["OPENAI_API_KEY", "OMNIROUTE_API_KEY"]}
    try:
        available = AdversarialAnalyst._check_llm_available()
        assert not available
    finally:
        for k, v in keys_backup.items():
            if v is not None:
                os.environ[k] = v


@pytest.mark.asyncio
async def test_cia_analysis_model_defaults():
    analysis = CIAAnalysis()
    assert analysis.classification_line == "UNCLASSIFIED // OSINT // LAWFUL USE ONLY"
    assert analysis.analytical_method == "deterministic"
    assert isinstance(analysis.intelligence_gaps, list)
