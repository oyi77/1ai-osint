"""Tests for AI analysis orchestrator."""

from unittest.mock import MagicMock

import pytest

from src.ai.orchestrator import AnalysisOrchestrator, PipelineState
from src.ai.schemas.responses import (
    CorrelationResult,
    EntityExtractionResult,
    EntityType,
    ExtractedEntity,
)
from src.ai.analyzers.risk_scorer import RiskScore
from src.core.models import Finding, ScanResult, Severity


@pytest.fixture
def mock_client():
    return MagicMock()


@pytest.fixture
def mock_extractor():
    return MagicMock()


@pytest.fixture
def mock_correlator():
    return MagicMock()


@pytest.fixture
def mock_scorer():
    return MagicMock()


@pytest.fixture
def orchestrator(mock_client, mock_extractor, mock_correlator, mock_scorer):
    return AnalysisOrchestrator(
        client=mock_client,
        extractor=mock_extractor,
        correlator=mock_correlator,
        scorer=mock_scorer,
    )


@pytest.fixture
def sample_scan_result():
    return ScanResult(
        scan_id="scan-1",
        module="data_leaks",
        target="test@example.com",
        status="ok",
        findings=[
            Finding(
                id="f1",
                module="data_leaks",
                title="Breach found",
                severity=Severity.HIGH,
                confidence=0.9,
                raw_data={"email": "test@example.com"},
                tags=["breach"],
            ),
        ],
    )


class TestPipelineState:
    def test_default_values(self):
        state = PipelineState()
        assert state.raw_data == ""
        assert state.scan_results == []
        assert state.extraction_result is None
        assert state.correlation_result is None
        assert state.risk_score is None
        assert state.report == {}
        assert state.error is None

    def test_with_values(self):
        state = PipelineState(raw_data="test data", error="some error")
        assert state.raw_data == "test data"
        assert state.error == "some error"


class TestAnalysisOrchestrator:
    @pytest.mark.asyncio
    async def test_run_with_raw_data(
        self, orchestrator, mock_extractor, mock_correlator, mock_scorer
    ):
        mock_extractor.extract.return_value = EntityExtractionResult(
            entities=[
                ExtractedEntity(
                    entity_type=EntityType.EMAIL, value="a@b.com", confidence=0.9
                )
            ],
            summary="Found 1 entity",
        )
        mock_correlator.correlate.return_value = CorrelationResult(
            correlated_groups=[["a@b.com"]],
            summary="Found 1 group",
        )
        mock_scorer.score.return_value = RiskScore(
            overall_score=50.0,
            risk_level="medium",
            total_findings=0,
        )

        result = await orchestrator.run(raw_data="Email: a@b.com")

        assert "entities" in result
        assert "correlation" in result
        assert "risk" in result
        assert "summary" in result
        assert len(result["entities"]) == 1

    @pytest.mark.asyncio
    async def test_run_with_scan_results(
        self,
        orchestrator,
        mock_extractor,
        mock_correlator,
        mock_scorer,
        sample_scan_result,
    ):
        mock_extractor.extract_from_findings.return_value = EntityExtractionResult(
            entities=[
                ExtractedEntity(
                    entity_type=EntityType.EMAIL,
                    value="test@example.com",
                    confidence=0.9,
                )
            ],
            summary="Found 1 entity",
        )
        mock_correlator.correlate.return_value = CorrelationResult(summary="No groups")
        mock_scorer.score.return_value = RiskScore(
            overall_score=75.0,
            risk_level="high",
            total_findings=1,
            critical_findings=0,
            high_findings=1,
        )

        result = await orchestrator.run(scan_results=[sample_scan_result])

        assert result["risk"]["risk_level"] == "high"
        mock_scorer.score.assert_called_once_with([sample_scan_result])

    @pytest.mark.asyncio
    async def test_run_no_data(
        self, orchestrator, mock_extractor, mock_correlator, mock_scorer
    ):
        mock_extractor.extract.return_value = EntityExtractionResult(
            entities=[], summary="No data"
        )
        mock_correlator.correlate.return_value = CorrelationResult(
            summary="No entities"
        )
        mock_scorer.score.return_value = RiskScore(
            overall_score=0.0, risk_level="minimal"
        )

        result = await orchestrator.run()

        assert result["risk"]["risk_level"] == "minimal"

    def test_ingest_stage(self, orchestrator):
        state = {"raw_data": "test", "scan_results": []}
        result = orchestrator._ingest(state)
        assert result["error"] is None

    def test_extract_stage_with_raw_data(self, orchestrator, mock_extractor):
        mock_extractor.extract.return_value = EntityExtractionResult(
            entities=[
                ExtractedEntity(
                    entity_type=EntityType.EMAIL, value="x@y.com", confidence=0.5
                )
            ],
            summary="Found",
        )
        state = {"raw_data": "Email: x@y.com", "scan_results": []}
        result = orchestrator._extract(state)

        assert result["extraction_result"] is not None
        assert len(result["extraction_result"].entities) == 1

    def test_extract_stage_no_data(self, orchestrator, mock_extractor):
        state = {"raw_data": "", "scan_results": []}
        result = orchestrator._extract(state)
        assert "No data to extract" in result["extraction_result"].summary

    def test_correlate_stage(self, orchestrator, mock_correlator):
        mock_correlator.correlate.return_value = CorrelationResult(summary="test")
        state = {
            "extraction_result": EntityExtractionResult(
                entities=[
                    ExtractedEntity(
                        entity_type=EntityType.EMAIL, value="a@b.com", confidence=0.5
                    )
                ]
            )
        }
        result = orchestrator._correlate(state)
        assert result["correlation_result"].summary == "test"

    def test_score_stage(self, orchestrator, mock_scorer, sample_scan_result):
        mock_scorer.score.return_value = RiskScore(
            overall_score=60.0, risk_level="high"
        )
        state = {"scan_results": [sample_scan_result]}
        result = orchestrator._score(state)
        assert result["risk_score"].risk_level == "high"

    def test_report_stage(self, orchestrator):
        extraction = EntityExtractionResult(
            entities=[
                ExtractedEntity(
                    entity_type=EntityType.EMAIL, value="a@b.com", confidence=0.9
                )
            ],
            summary="Found 1",
        )
        correlation = CorrelationResult(
            correlated_groups=[["a@b.com"]],
            summary="1 group",
        )
        risk = RiskScore(overall_score=50.0, risk_level="medium", total_findings=1)

        state = {
            "extraction_result": extraction,
            "correlation_result": correlation,
            "risk_score": risk,
        }
        result = orchestrator._report(state)

        report = result["report"]
        assert len(report["entities"]) == 1
        assert report["correlation"]["summary"] == "1 group"
        assert report["risk"]["risk_level"] == "medium"
        assert "Extracted 1 entities" in report["summary"]
