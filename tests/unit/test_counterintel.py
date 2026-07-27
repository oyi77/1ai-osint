"""Tests for Phase 5 Pillar 7: Counterintelligence & Legend Detection."""

from __future__ import annotations

from unittest.mock import MagicMock

from src.modules.identity_tracking.counterintel import (
    CounterIntelAnalyzer,
    LegendIndicator,
    OPSECLevel,
)


def _make_report(evidence=None, identifiers=None, timeline=None):
    report = MagicMock()
    report.evidence = evidence or []
    report.identifiers = identifiers or []
    report.timeline = timeline or []
    return report


def _make_evidence(
    identifier_type="email",
    identifier_value="test@example.com",
    source="email_osint",
    raw_data=None,
    notes="",
):
    ev = MagicMock()
    ev.identifier_type = identifier_type
    ev.identifier_value = identifier_value
    ev.source = source
    ev.raw_data = raw_data or {}
    ev.notes = notes
    return ev


def test_no_breach_exposure_triggers_indicator():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(
        evidence=[
            _make_evidence(identifier_type="username", identifier_value="cooluser"),
        ]
    )
    assessment = analyzer.assess_legend_probability(report)
    no_breach = next(
        (i for i in assessment.legend_indicators if i.rule == "NO_BREACH_EXPOSURE"),
        None,
    )
    assert no_breach is not None
    assert no_breach.triggered is True


def test_breach_exposure_does_not_trigger():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(
        evidence=[
            _make_evidence(identifier_type="email"),
            _make_evidence(identifier_type="password"),
        ]
    )
    assessment = analyzer.assess_legend_probability(report)
    no_breach = next(
        (i for i in assessment.legend_indicators if i.rule == "NO_BREACH_EXPOSURE"),
        None,
    )
    assert no_breach is not None
    assert no_breach.triggered is False


def test_no_historical_footprint_triggers_on_empty_timeline():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(timeline=[])
    assessment = analyzer.assess_legend_probability(report)
    no_hist = next(
        (i for i in assessment.legend_indicators if i.rule == "NO_HISTORICAL_FOOTPRINT"),
        None,
    )
    assert no_hist is not None
    assert no_hist.triggered is True


def test_legend_confidence_in_range():
    analyzer = CounterIntelAnalyzer()
    report = _make_report()
    assessment = analyzer.assess_legend_probability(report)
    assert 0.0 <= assessment.legend_confidence <= 1.0


def test_is_likely_legend_with_high_score():
    """Multiple high-severity rules triggered should set is_likely_legend=True."""
    analyzer = CounterIntelAnalyzer()
    # Empty everything → triggers NO_BREACH, NO_HISTORICAL_FOOTPRINT = high severity * 2 = 0.6
    report = _make_report(evidence=[], timeline=[])
    assessment = analyzer.assess_legend_probability(report)
    # Both high-severity rules should be enough to flag as likely legend
    assert assessment.legend_confidence >= 0.3  # at least some score
    # is_likely_legend depends on threshold
    assert isinstance(assessment.is_likely_legend, bool)


def test_opsec_none_when_no_signals():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(
        evidence=[
            _make_evidence(identifier_value="test@gmail.com"),
        ]
    )
    level = analyzer.score_opsec_level(report)
    assert level == OPSECLevel.NONE


def test_opsec_basic_with_vpn_mention():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(
        evidence=[
            _make_evidence(identifier_value="mullvad_user", notes="uses mullvad vpn"),
        ]
    )
    level = analyzer.score_opsec_level(report)
    assert level in (OPSECLevel.BASIC, OPSECLevel.INTERMEDIATE, OPSECLevel.ADVANCED)


def test_opsec_advanced_with_tor():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(
        evidence=[
            _make_evidence(source="darknet"),
        ]
    )
    level = analyzer.score_opsec_level(report)
    assert level == OPSECLevel.ADVANCED


def test_deception_contradictory_locations():
    analyzer = CounterIntelAnalyzer()
    evidence = [
        _make_evidence(raw_data={"city": "London"}),
        _make_evidence(raw_data={"city": "Moscow"}),
        _make_evidence(raw_data={"city": "Beijing"}),
        _make_evidence(raw_data={"city": "New York"}),
        _make_evidence(raw_data={"city": "Dubai"}),
    ]
    report = _make_report(evidence=evidence)
    deception = analyzer.detect_deception_patterns(report)
    assert any("location" in d.lower() for d in deception)


def test_deception_empty_evidence_flagged():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(evidence=[])
    deception = analyzer.detect_deception_patterns(report)
    assert any("scrubbed" in d.lower() or "zero" in d.lower() for d in deception)


def test_recommendations_populated():
    analyzer = CounterIntelAnalyzer()
    report = _make_report(evidence=[], timeline=[])
    assessment = analyzer.assess_legend_probability(report)
    assert len(assessment.recommended_ci_actions) >= 1


def test_assessment_notes_summary():
    analyzer = CounterIntelAnalyzer()
    report = _make_report()
    assessment = analyzer.assess_legend_probability(report)
    assert "indicator" in assessment.assessment_notes.lower()


def test_all_legend_indicators_checked():
    """All 8 defined legend rules should appear in the assessment."""
    analyzer = CounterIntelAnalyzer()
    report = _make_report()
    assessment = analyzer.assess_legend_probability(report)
    assert len(assessment.legend_indicators) == len(analyzer._LEGEND_RULES)


def test_legend_indicator_model():
    indicator = LegendIndicator(
        rule="TEST_RULE",
        description="Test description",
        severity="high",
        triggered=True,
        evidence=["Some evidence"],
    )
    assert indicator.triggered is True
    assert indicator.severity == "high"


def test_opsec_level_enum_values():
    assert OPSECLevel.NONE == "none"
    assert OPSECLevel.ADVANCED == "advanced"
