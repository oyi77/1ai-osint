"""Tests for Phase 5 Pillar 6: Predictive Threat Modeling."""

from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.deep_scan.threat_model import (
    PredictiveThreatModeler,
    ThreatArchetype,
    ThreatTrajectory,
)


def _make_report(risk_score=0.5, evidence_types=None, sources=None):
    report = MagicMock()
    risk = MagicMock()
    risk.score = risk_score
    report.risk = risk
    evidence = []
    for etype, source in zip(evidence_types or [], sources or []):
        ev = MagicMock()
        ev.identifier_type = etype
        ev.source = source
        ev.identifier_value = "test@example.com"
        evidence.append(ev)
    report.evidence = evidence
    return report


def test_score_archetypes_returns_all_archetypes():
    modeler = PredictiveThreatModeler()
    report = _make_report(risk_score=0.5)
    scores = modeler.score_archetypes(report)
    assert ThreatArchetype.FINANCIAL_FRAUD in scores
    assert ThreatArchetype.STATE_ACTOR in scores
    assert ThreatArchetype.INSIDER_THREAT in scores
    assert ThreatArchetype.HACKTIVIST in scores


def test_score_archetypes_range_zero_to_one():
    modeler = PredictiveThreatModeler()
    report = _make_report(risk_score=0.8)
    scores = modeler.score_archetypes(report)
    for score in scores.values():
        assert 0.0 <= score <= 1.0


def test_crypto_exposure_boosts_financial_fraud_score():
    modeler = PredictiveThreatModeler()
    report = _make_report(
        risk_score=0.3,
        evidence_types=["crypto_address"] * 5,
        sources=["crypto_balance"] * 5,
    )
    scores = modeler.score_archetypes(report)
    assert scores[ThreatArchetype.FINANCIAL_FRAUD] > scores[ThreatArchetype.HACKTIVIST]


def test_predict_trajectory_low_risk_is_unknown():
    modeler = PredictiveThreatModeler()
    report = _make_report(risk_score=0.0)
    trajectory = modeler.predict_trajectory(report)
    # With no evidence and zero risk, confidence should be low
    assert trajectory.confidence == "low"
    assert trajectory.most_likely_archetype == ThreatArchetype.UNKNOWN


def test_predict_trajectory_has_next_actions():
    modeler = PredictiveThreatModeler()
    report = _make_report(risk_score=0.5)
    trajectory = modeler.predict_trajectory(report)
    assert isinstance(trajectory.predicted_next_actions, list)
    # Unknown archetype still returns fallback actions
    assert len(trajectory.predicted_next_actions) >= 1


def test_predict_trajectory_model_valid():
    modeler = PredictiveThreatModeler()
    report = _make_report(risk_score=0.4)
    trajectory = modeler.predict_trajectory(report)
    assert isinstance(trajectory, ThreatTrajectory)
    assert trajectory.reasoning != ""
    assert trajectory.analytical_method == "deterministic"
    assert all(0.0 <= s <= 1.0 for s in trajectory.archetype_scores.values())


def test_high_risk_indicators_populated():
    modeler = PredictiveThreatModeler()
    # High risk score + darknet source
    report = _make_report(
        risk_score=0.9,
        evidence_types=["url"],
        sources=["darknet"],
    )
    trajectory = modeler.predict_trajectory(report)
    assert any(
        "risk score" in ind.lower() or "darknet" in ind.lower()
        for ind in trajectory.high_risk_indicators
    )


def test_confidence_high_when_score_above_threshold():
    modeler = PredictiveThreatModeler()
    # Inject many crypto sources to push financial fraud score high
    report = _make_report(
        risk_score=0.8,
        evidence_types=["crypto_address"] * 10,
        sources=["crypto_balance"] * 10,
    )
    trajectory = modeler.predict_trajectory(report)
    # Financial fraud should have higher confidence
    assert trajectory.confidence in ("medium", "high")


@pytest.mark.asyncio
async def test_llm_enhanced_fallback_no_key():
    modeler = PredictiveThreatModeler()
    report = _make_report()
    trajectory = modeler.predict_trajectory(report)
    import os

    keys_backup = {
        k: os.environ.pop(k, None) for k in ["OPENAI_API_KEY", "OMNIROUTE_API_KEY"]
    }
    try:
        result = await modeler.llm_enhanced_prediction(report, trajectory)
        assert result.analytical_method == "deterministic"  # unchanged
    finally:
        for k, v in keys_backup.items():
            if v is not None:
                os.environ[k] = v


@pytest.mark.asyncio
async def test_llm_enhanced_handles_exception():
    modeler = PredictiveThreatModeler()
    report = _make_report(risk_score=0.5)
    trajectory = modeler.predict_trajectory(report)
    with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
        with patch(
            "src.ai.omniroute_client.OmniRouteClient.async_chat",
            new_callable=AsyncMock,
            side_effect=Exception("API down"),
        ):
            result = await modeler.llm_enhanced_prediction(report, trajectory)
    # Should return original trajectory unchanged
    assert isinstance(result, ThreatTrajectory)


def test_threat_archetype_enum_values():
    assert ThreatArchetype.FINANCIAL_FRAUD == "financial_fraud"
    assert ThreatArchetype.STATE_ACTOR == "state_actor"
    assert ThreatArchetype.INSIDER_THREAT == "insider_threat"
    assert ThreatArchetype.HACKTIVIST == "hacktivist"
    assert ThreatArchetype.UNKNOWN == "unknown"
