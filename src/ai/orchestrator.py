"""LangGraph state machine orchestrating the AI analysis pipeline."""

import logging
from typing import Any, Literal, Optional

from langgraph.graph import END, StateGraph

from src.ai.analyzers.correlation_engine import CorrelationEngine
from src.ai.analyzers.entity_extractor import EntityExtractor
from src.ai.analyzers.risk_scorer import RiskScorer, RiskScore
from src.ai.omniroute_client import OmniRouteClient
from src.ai.schemas.responses import CorrelationResult, EntityExtractionResult
from src.models import ScanResult

logger = logging.getLogger(__name__)


class PipelineState(dict):
    """State passed through the LangGraph pipeline."""

    @property
    def raw_data(self) -> str:
        return self.get("raw_data", "")

    @property
    def scan_results(self) -> list[ScanResult]:
        return self.get("scan_results", [])

    @property
    def extraction_result(self) -> Optional[EntityExtractionResult]:
        return self.get("extraction_result")

    @property
    def correlation_result(self) -> Optional[CorrelationResult]:
        return self.get("correlation_result")

    @property
    def risk_score(self) -> Optional[RiskScore]:
        return self.get("risk_score")

    @property
    def report(self) -> dict[str, Any]:
        return self.get("report", {})

    @property
    def error(self) -> Optional[str]:
        return self.get("error")


class AnalysisOrchestrator:
    """
    LangGraph state machine for AI-powered OSINT analysis.

    Pipeline stages:
    1. ingest    - Collect and normalize raw data / scan results
    2. extract   - LLM-based entity extraction
    3. correlate - Cross-module entity linking
    4. score     - Aggregate risk scoring
    5. report    - Generate final report
    """

    def __init__(
        self,
        client: Optional[OmniRouteClient] = None,
        extractor: Optional[EntityExtractor] = None,
        correlator: Optional[CorrelationEngine] = None,
        scorer: Optional[RiskScorer] = None,
    ):
        self._client = client or OmniRouteClient()
        self._extractor = extractor or EntityExtractor(self._client)
        self._correlator = correlator or CorrelationEngine(self._client)
        self._scorer = scorer or RiskScorer()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state graph."""
        graph = StateGraph(dict)

        graph.add_node("ingest", self._ingest)
        graph.add_node("extract", self._extract)
        graph.add_node("correlate", self._correlate)
        graph.add_node("score", self._score)
        graph.add_node("report", self._report)

        graph.set_entry_point("ingest")
        graph.add_edge("ingest", "extract")
        graph.add_edge("extract", "correlate")
        graph.add_edge("correlate", "score")
        graph.add_edge("score", "report")
        graph.add_edge("report", END)

        return graph.compile()

    async def run(
        self,
        raw_data: str = "",
        scan_results: Optional[list[ScanResult]] = None,
    ) -> dict[str, Any]:
        """
        Run the full analysis pipeline.

        Args:
            raw_data: Raw OSINT text for entity extraction.
            scan_results: Pre-computed ScanResults for risk scoring.
        Returns:
            Final report dict with extraction, correlation, and risk data.
        """
        initial_state: dict[str, Any] = {
            "raw_data": raw_data,
            "scan_results": scan_results or [],
        }

        try:
            final_state = await self._graph.ainvoke(initial_state)
            return final_state.get("report", {"error": "No report generated"})
        except Exception as e:
            logger.error("Pipeline execution failed: %s", e)
            return {"error": str(e)}

    def _ingest(self, state: dict) -> dict:
        """Ingest stage: validate and normalize inputs."""
        logger.info("Pipeline: ingest stage")
        state["error"] = None
        return state

    def _extract(self, state: dict) -> dict:
        """Extract stage: LLM-based entity extraction."""
        logger.info("Pipeline: extract stage")
        raw_data = state.get("raw_data", "")
        scan_results = state.get("scan_results", [])

        if raw_data:
            extraction_result = self._extractor.extract(raw_data)
        elif scan_results:
            findings = []
            for sr in scan_results:
                for f in sr.findings:
                    findings.append(f.model_dump())
            extraction_result = self._extractor.extract_from_findings(findings)
        else:
            extraction_result = EntityExtractionResult(
                entities=[], summary="No data to extract from"
            )

        state["extraction_result"] = extraction_result
        return state

    def _correlate(self, state: dict) -> dict:
        """Correlate stage: cross-module entity linking."""
        logger.info("Pipeline: correlate stage")
        extraction_result = state.get("extraction_result")

        if extraction_result and extraction_result.entities:
            correlation_result = self._correlator.correlate(extraction_result)
        else:
            correlation_result = CorrelationResult(
                summary="No entities to correlate"
            )

        state["correlation_result"] = correlation_result
        return state

    def _score(self, state: dict) -> dict:
        """Score stage: aggregate risk scoring."""
        logger.info("Pipeline: score stage")
        scan_results = state.get("scan_results", [])

        if scan_results:
            risk_score = self._scorer.score(scan_results)
        else:
            risk_score = RiskScore(
                overall_score=0.0,
                risk_level="minimal",
                summary="No scan results to score",
            )

        state["risk_score"] = risk_score
        return state

    def _report(self, state: dict) -> dict:
        """Report stage: generate final report."""
        logger.info("Pipeline: report stage")
        extraction = state.get("extraction_result")
        correlation = state.get("correlation_result")
        risk_score = state.get("risk_score")

        report: dict[str, Any] = {
            "entities": [],
            "correlation": {},
            "risk": {},
            "summary": "",
        }

        if extraction:
            report["entities"] = [e.model_dump() for e in extraction.entities]
            report["entity_summary"] = extraction.summary

        if correlation:
            report["correlation"] = {
                "groups": correlation.correlated_groups,
                "relationships": correlation.relationships,
                "summary": correlation.summary,
            }

        if risk_score:
            report["risk"] = risk_score.to_dict()

        # Build combined summary
        lines: list[str] = []
        if extraction and extraction.entities:
            lines.append(f"Extracted {len(extraction.entities)} entities")
        if correlation and correlation.correlated_groups:
            lines.append(f"Found {len(correlation.correlated_groups)} correlated groups")
        if risk_score:
            lines.append(f"Risk level: {risk_score.risk_level} ({risk_score.overall_score:.1f}/100)")
        report["summary"] = ". ".join(lines) if lines else "No analysis performed"

        state["report"] = report
        return state
