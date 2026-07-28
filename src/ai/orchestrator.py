"""LangGraph state machine orchestrating the AI analysis pipeline.

Pipeline stages:
1. ingest      - Collect and normalize raw data / scan results
2. extract     - LLM-based entity extraction
3. correlate   - Cross-module entity linking
4. profile     - (optional) Behavioral profiling
5. anomaly     - (optional) Anomaly detection
6. score       - Aggregate risk scoring
7. report      - Generate final report
"""
# mypy: disable-error-code="type-var"

import logging
from typing import Any

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.ai.analyzers.anomaly_detector import AnomalyDetector
from src.ai.analyzers.behavioral_profiler import BehavioralProfiler
from src.ai.analyzers.correlation_engine import CorrelationEngine
from src.ai.analyzers.entity_extractor import EntityExtractor
from src.ai.analyzers.risk_scorer import RiskScore, RiskScorer
from src.ai.omniroute_client import OmniRouteClient
from src.ai.schemas.responses import (
    AnomalyDetectionResult,
    BehavioralAnalysisResult,
    CorrelationResult,
    EntityExtractionResult,
)
from src.core.models import ScanResult

logger = logging.getLogger(__name__)


# State is a plain dict — LangGraph handles it internally as dict[str, Any].
# PipelineState is kept as a view-only wrapper for property access.
StateT = dict


class PipelineState(dict):
    """State passed through the LangGraph pipeline."""

    @property
    def raw_data(self) -> str:
        return self.get("raw_data", "")

    @property
    def scan_results(self) -> list[ScanResult]:
        return self.get("scan_results", [])

    @property
    def extraction_result(self) -> EntityExtractionResult | None:
        return self.get("extraction_result")

    @property
    def correlation_result(self) -> CorrelationResult | None:
        return self.get("correlation_result")

    @property
    def behavioral_result(self) -> BehavioralAnalysisResult | None:
        return self.get("behavioral_result")

    @property
    def anomaly_result(self) -> AnomalyDetectionResult | None:
        return self.get("anomaly_result")

    @property
    def risk_score(self) -> RiskScore | None:
        return self.get("risk_score")

    @property
    def report(self) -> dict[str, Any]:
        return self.get("report", {})

    @property
    def error(self) -> str | None:
        return self.get("error")


class AnalysisOrchestrator:
    """LangGraph state machine for AI-powered OSINT analysis.

    Pipeline stages:
    1. ingest    - Collect and normalize raw data / scan results
    2. extract   - LLM-based entity extraction
    3. correlate - Cross-module entity linking
    4. profile   - (optional) Behavioral profiling
    5. anomaly   - (optional) Anomaly detection
    6. score     - Aggregate risk scoring
    7. report    - Generate final report

    The 'profile' and 'anomaly' stages are optional and gated by
    enable_behavioral_profiling and enable_anomaly_detection flags.
    The core pipeline (ingest → extract → correlate → score → report)
    remains intact and runs identically regardless of these flags.
    """

    def __init__(
        self,
        client: OmniRouteClient | None = None,
        extractor: EntityExtractor | None = None,
        correlator: CorrelationEngine | None = None,
        scorer: RiskScorer | None = None,
        profiler: BehavioralProfiler | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        enable_behavioral_profiling: bool = False,
        enable_anomaly_detection: bool = False,
    ):
        self._client = client or OmniRouteClient()
        self._extractor = extractor or EntityExtractor(self._client)
        self._correlator = correlator or CorrelationEngine(self._client)
        self._scorer = scorer or RiskScorer()
        self._profiler = profiler or BehavioralProfiler(self._client)
        self._anomaly_detector = anomaly_detector or AnomalyDetector(self._client)
        self._enable_behavioral = enable_behavioral_profiling
        self._enable_anomaly = enable_anomaly_detection
        self._graph: CompiledStateGraph = self._build_graph()

    async def _call_llm(self, prompt: str) -> str | None:
        """Call the LLM with a plain-text prompt via OmniRouteClient."""
        try:
            return await self._client.async_chat([{"role": "user", "content": prompt}])
        except Exception:
            return None

    def _build_graph(self) -> CompiledStateGraph:
        """Build the LangGraph state graph."""
        graph: StateGraph = StateGraph(dict)

        graph.add_node("ingest", self._ingest)
        graph.add_node("extract", self._extract)
        graph.add_node("correlate", self._correlate)

        # Core pipeline always goes: ingest → extract → correlate → score → report
        if self._enable_behavioral and self._enable_anomaly:
            # Extended: ingest → extract → correlate → profile → anomaly → score → report
            graph.add_node("profile", self._profile)
            graph.add_node("anomaly", self._anomaly)
            graph.add_node("score", self._score)
            graph.add_node("report", self._report)

            graph.set_entry_point("ingest")
            graph.add_edge("ingest", "extract")
            graph.add_edge("extract", "correlate")
            graph.add_edge("correlate", "profile")
            graph.add_edge("profile", "anomaly")
            graph.add_edge("anomaly", "score")
            graph.add_edge("score", "report")
            graph.add_edge("report", END)
        elif self._enable_behavioral:
            # ingest → extract → correlate → profile → score → report
            graph.add_node("profile", self._profile)
            graph.add_node("score", self._score)
            graph.add_node("report", self._report)

            graph.set_entry_point("ingest")
            graph.add_edge("ingest", "extract")
            graph.add_edge("extract", "correlate")
            graph.add_edge("correlate", "profile")
            graph.add_edge("profile", "score")
            graph.add_edge("score", "report")
            graph.add_edge("report", END)
        elif self._enable_anomaly:
            # ingest → extract → correlate → anomaly → score → report
            graph.add_node("anomaly", self._anomaly)
            graph.add_node("score", self._score)
            graph.add_node("report", self._report)

            graph.set_entry_point("ingest")
            graph.add_edge("ingest", "extract")
            graph.add_edge("extract", "correlate")
            graph.add_edge("correlate", "anomaly")
            graph.add_edge("anomaly", "score")
            graph.add_edge("score", "report")
            graph.add_edge("report", END)
        else:
            # Original pipeline: ingest → extract → correlate → score → report
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
        scan_results: list[ScanResult] | None = None,
    ) -> dict[str, Any]:
        """Run the full analysis pipeline.

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

    def _ingest(self, state: dict[str, Any]) -> dict[str, Any]:
        """Ingest stage: validate and normalize inputs."""
        logger.info("Pipeline: ingest stage")
        state["error"] = None
        return state

    def _extract(self, state: dict[str, Any]) -> dict[str, Any]:
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
            extraction_result = EntityExtractionResult(entities=[], summary="No data to extract from")

        state["extraction_result"] = extraction_result
        return state

    def _correlate(self, state: dict[str, Any]) -> dict[str, Any]:
        """Correlate stage: cross-module entity linking."""
        logger.info("Pipeline: correlate stage")
        extraction_result = state.get("extraction_result")

        if extraction_result and extraction_result.entities:
            correlation_result = self._correlator.correlate(extraction_result)
        else:
            correlation_result = CorrelationResult(summary="No entities to correlate")

        state["correlation_result"] = correlation_result
        return state

    def _profile(self, state: dict[str, Any]) -> dict[str, Any]:
        """Profile stage: behavioral profiling (optional)."""
        logger.info("Pipeline: profile stage")
        extraction_result = state.get("extraction_result")

        if extraction_result and extraction_result.entities:
            # Build entity data from extraction results for profiling
            entity_data = []
            for entity in extraction_result.entities:
                entity_data.append(
                    {
                        "text": f"{entity.value} {entity.context}",
                        "source": entity.entity_type.value,
                    }
                )

            result = self._profiler.analyze_entity(entity_data, entity_key="default")
        else:
            result = BehavioralAnalysisResult(summary="No entities to profile")

        state["behavioral_result"] = result
        return state

    def _anomaly(self, state: dict[str, Any]) -> dict[str, Any]:
        """Anomaly stage: anomaly detection (optional)."""
        logger.info("Pipeline: anomaly stage")
        behavioral_result = state.get("behavioral_result")
        scan_results = state.get("scan_results", [])

        # Build entity data from scan results
        entity_data = []
        for sr in scan_results:
            for f in sr.findings:
                entity_data.append(
                    {
                        "text": f"{f.title} {f.description}",
                        "source": f.module,
                        "timestamp": f.timestamp.isoformat() if hasattr(f.timestamp, "isoformat") else str(f.timestamp),
                    }
                )

        baseline = None
        if behavioral_result:
            baseline = behavioral_result.profiles.get("default")

        result = self._anomaly_detector.detect(
            entity_data,
            baseline=baseline,
            entity_key="default",
            use_llm=False,  # Keep deterministic by default for speed
        )

        state["anomaly_result"] = result
        return state

    def _score(self, state: dict[str, Any]) -> dict[str, Any]:
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

    def _report(self, state: dict[str, Any]) -> dict[str, Any]:
        """Report stage: generate final report."""
        logger.info("Pipeline: report stage")
        extraction = state.get("extraction_result")
        correlation = state.get("correlation_result")
        risk_score = state.get("risk_score")
        behavioral = state.get("behavioral_result")
        anomaly = state.get("anomaly_result")

        report: dict[str, Any] = {
            "entities": [],
            "correlation": {},
            "behavioral": {},
            "anomaly": {},
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

        if behavioral:
            report["behavioral"] = {key: profile.model_dump() for key, profile in behavioral.profiles.items()}

        if anomaly:
            report["anomaly"] = {key: report_item.model_dump() for key, report_item in anomaly.reports.items()}

        if risk_score:
            report["risk"] = risk_score.to_dict()

        # Build combined summary
        lines: list[str] = []
        if extraction and extraction.entities:
            lines.append(f"Extracted {len(extraction.entities)} entities")
        if correlation and correlation.correlated_groups:
            lines.append(f"Found {len(correlation.correlated_groups)} correlated groups")
        if behavioral and behavioral.profiles:
            lines.append(f"Profiled {len(behavioral.profiles)} entities")
        if anomaly:
            for key, r in anomaly.reports.items():
                if r.detected_anomalies:
                    lines.append(f"Detected {len(r.detected_anomalies)} anomalies for {key}")
        if risk_score:
            lines.append(f"Risk level: {risk_score.risk_level} ({risk_score.overall_score:.1f}/100)")
        report["summary"] = ". ".join(lines) if lines else "No analysis performed"

        state["report"] = report
        return state
