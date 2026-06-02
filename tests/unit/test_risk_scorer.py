"""Tests for risk scorer module."""

import pytest

from src.ai.analyzers.risk_scorer import RiskScorer
from src.models import Finding, ScanResult, Severity


@pytest.fixture
def scorer():
    return RiskScorer()


@pytest.fixture
def critical_findings():
    return [
        Finding(
            id="f1",
            module="data_leaks",
            title="Critical breach",
            severity=Severity.CRITICAL,
            confidence=0.95,
            tags=["breach"],
        ),
        Finding(
            id="f2",
            module="data_leaks",
            title="High breach",
            severity=Severity.HIGH,
            confidence=0.85,
            tags=["breach"],
        ),
    ]


@pytest.fixture
def sample_scan_results(critical_findings):
    return [
        ScanResult(
            scan_id="scan-1",
            module="data_leaks",
            target="test@example.com",
            status="ok",
            findings=critical_findings,
        ),
        ScanResult(
            scan_id="scan-2",
            module="gitleaks",
            target="test-repo",
            status="ok",
            findings=[
                Finding(
                    id="f3",
                    module="gitleaks",
                    title="Leaked secret",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    tags=["secret"],
                ),
            ],
        ),
    ]


class TestRiskScorer:
    def test_score_empty(self, scorer):
        result = scorer.score([])
        assert result.overall_score == 0.0
        assert result.risk_level == "minimal"
        assert "No scan results" in result.summary

    def test_score_with_results(self, scorer, sample_scan_results):
        result = scorer.score(sample_scan_results)

        assert result.overall_score > 0.0
        assert result.total_findings == 3
        assert result.critical_findings == 1
        assert result.high_findings == 2
        assert "data_leaks" in result.modules_contributed
        assert "gitleaks" in result.modules_contributed
        assert len(result.breakdowns) > 0

    def test_score_single(self, scorer, critical_findings):
        scan = ScanResult(
            scan_id="s1",
            module="data_leaks",
            target="test@example.com",
            findings=critical_findings,
        )
        result = scorer.score_single(scan)

        assert result.total_findings == 2
        assert result.critical_findings == 1

    def test_risk_levels(self, scorer):
        # Test each risk level threshold
        assert RiskScorer._score_to_level(90.0) == "critical"
        assert RiskScorer._score_to_level(70.0) == "high"
        assert RiskScorer._score_to_level(50.0) == "medium"
        assert RiskScorer._score_to_level(30.0) == "low"
        assert RiskScorer._score_to_level(10.0) == "minimal"

    def test_custom_weights(self):
        custom_weights = {"data_leaks": 2.0, "gitleaks": 0.1}
        scorer = RiskScorer(module_weights=custom_weights)

        results = [
            ScanResult(
                scan_id="s1",
                module="data_leaks",
                target="test",
                findings=[
                    Finding(id="f1", module="data_leaks", title="t", severity=Severity.HIGH, confidence=0.9),
                ],
            )
        ]

        result = scorer.score(results)
        assert result.overall_score > 0.0

    def test_score_to_dict(self, scorer, sample_scan_results):
        result = scorer.score(sample_scan_results)
        d = result.to_dict()

        assert "overall_score" in d
        assert "risk_level" in d
        assert "breakdowns" in d
        assert isinstance(d["breakdowns"], list)

    def test_info_only_findings_low_score(self, scorer):
        results = [
            ScanResult(
                scan_id="s1",
                module="data_leaks",
                target="test",
                findings=[
                    Finding(id="f1", module="data_leaks", title="info", severity=Severity.INFO, confidence=0.3),
                ],
            )
        ]
        result = scorer.score(results)
        assert result.risk_level == "minimal"
        assert result.critical_findings == 0

    def test_build_summary(self, scorer, sample_scan_results):
        result = scorer.score(sample_scan_results)
        assert "Overall risk" in result.summary
        assert "Total findings" in result.summary
        assert "Category breakdown" in result.summary

    def test_breakdown_top_severity(self, scorer, critical_findings):
        results = [
            ScanResult(
                scan_id="s1",
                module="data_leaks",
                target="test",
                findings=critical_findings,
            )
        ]
        result = scorer.score(results)

        data_exposure = [b for b in result.breakdowns if b.category == "data_exposure"]
        assert len(data_exposure) == 1
        assert data_exposure[0].top_severity == "critical"
