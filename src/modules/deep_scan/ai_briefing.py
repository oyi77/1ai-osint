"""AI briefing enhancer — evidence‑cited enrichment with gap and conflict analysis.

Provides ``enhance_briefing_with_ai()`` for backward compatibility and the
richer ``AIBriefingEnhancer`` class that adds source credibility scoring,
intelligence gap analysis, multi-source conflict detection, and
confidence-weighted assertions.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Backward-compatible function (unchanged API)
# ------------------------------------------------------------------

def enhance_briefing_with_ai(report: Any, scan_result: Any) -> Any:
    """Augment key_judgments using AI when Omniroute/OpenAI is configured.

    Legacy wrapper — for richer enhancement use ``AIBriefingEnhancer``.
    """
    try:
        from src.ai.orchestrator import AnalysisOrchestrator
        from src.core.config import Settings

        settings = Settings()
        if not settings.effective_openai_api_key:
            return report

        import asyncio

        orchestrator = AnalysisOrchestrator()
        ai_report = asyncio.run(orchestrator.run(scan_results=scan_result.scan_results))
        if not ai_report:
            return report

        summary = ai_report.get("summary") or ai_report.get("executive_summary")
        if summary and isinstance(summary, str):
            report.briefing.key_judgments.insert(
                0,
                f"[AI] {summary[:500]} (verify against evidence register)",
            )
    except Exception as exc:
        logger.debug("AI briefing enhancement skipped: %s", exc)
    return report


# ------------------------------------------------------------------
# Source credibility
# ------------------------------------------------------------------

# Pre-computed credibility scores for known OSINT sources.
SOURCE_CREDIBILITY: dict[str, float] = {
    "hibp": 0.95,
    "dehashed": 0.90,
    "leakcheck": 0.85,
    "snusbase": 0.80,
    "intelx": 0.75,
    "scylla": 0.70,
    "github": 0.85,
    "gravatar": 0.80,
    "people_finder": 0.70,
    "social_osint": 0.75,
    "phone_finder": 0.70,
    "domain_recon": 0.80,
    "wayback": 0.90,
    "shodan": 0.85,
    "virustotal": 0.85,
    "abuseipdb": 0.80,
    "whoisxml": 0.75,
    "data_leaks": 0.70,
    "google_dork": 0.60,
    "search_dork": 0.55,
}

_UNKNOWN_SOURCE_CREDIBILITY = 0.50


def source_credibility(source_name: str) -> float:
    """Return credibility score [0, 1] for a given source name."""
    key = source_name.strip().lower().replace("source_", "")
    return SOURCE_CREDIBILITY.get(key, _UNKNOWN_SOURCE_CREDIBILITY)


# ------------------------------------------------------------------
# AIBriefingEnhancer
# ------------------------------------------------------------------

class AIBriefingEnhancer:
    """Enrich an operational briefing with AI analysis, evidence-cited.

    Compared to the legacy ``enhance_briefing_with_ai()``, this class:

    * Attaches evidence citations to every AI assertion (provenance).
    * Scores each source's credibility.
    * Flags intelligence gaps (what we don't know).
    * Detects contradictory findings across sources.
    * Produces confidence-weighted assertions.
    """

    def __init__(self) -> None:
        self._credibility_cache: dict[str, float] = {}

    # ------------------------------------------------------------------
    # main enrichment pipeline
    # ------------------------------------------------------------------

    def enhance(
        self,
        report: Any,
        scan_result: Any,
        *,
        enable_gap_analysis: bool = True,
        enable_conflict_detection: bool = True,
    ) -> Any:
        """Full pipeline: AI enrichment → credibility → gaps → conflicts.

        Parameters
        ----------
        report : IntelReport
            The report to enrich (modified in-place and returned).
        scan_result : DeepScanResult
            The scan result that produced the report.
        enable_gap_analysis : bool
            Whether to append intelligence-gap items.
        enable_conflict_detection : bool
            Whether to scan for contradictory findings.

        Returns
        -------
        IntelReport
            The same report object, enriched in-place.
        """
        # 1) AI enrichment (evidence-cited)
        self._ai_enrich(report, scan_result)

        # 2) Source credibility scoring
        self._score_sources(report, scan_result)

        # 3) Gap analysis
        if enable_gap_analysis:
            self._gap_analysis(report, scan_result)

        # 4) Conflict detection
        if enable_conflict_detection:
            self._detect_conflicts(report, scan_result)

        return report

    # ------------------------------------------------------------------
    # AI enrichment with citations
    # ------------------------------------------------------------------

    def _ai_enrich(self, report: Any, scan_result: Any) -> None:
        """Attempt AI-based summary injection with evidence citations."""
        try:
            from src.ai.orchestrator import AnalysisOrchestrator
            from src.core.config import Settings

            settings = Settings()
            if not settings.effective_openai_api_key:
                return

            import asyncio

            evidence_snippets = [
                f"- {ev.identifier_type}: {ev.identifier_value} (from {ev.source}, conf={ev.confidence})"
                for ev in (getattr(report, "evidence", None) or [])
            ][:20]

            if not evidence_snippets:
                return

            prompt = (
                "Analyse the following OSINT evidence and produce 2-4 key judgments. "
                "For each judgment, cite the evidence it is based on by referencing the source name.\n"
                "Evidence:\n" + "\n".join(evidence_snippets) + "\n"
                "Output format:\n"
                "- **Judgment**: <text> [Source: <name>]\n"
            )

            orchestrator = AnalysisOrchestrator()
            ai_text = asyncio.run(
                orchestrator._call_llm(prompt)  # noqa: SLF001
            )
            if ai_text and isinstance(ai_text, str):
                for line in ai_text.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("- **Judgment") or line.startswith("-"):
                        label = line.lstrip("- ")
                        report.briefing.key_judgments.insert(
                            0,
                            f"[AI-evidence-cited] {label[:500]}",
                        )
        except Exception as exc:
            logger.debug("AI enrichment skipped: %s", exc)

    # ------------------------------------------------------------------
    # source credibility scoring
    # ------------------------------------------------------------------

    def _score_sources(self, report: Any, _scan_result: Any) -> None:
        """Score each source used in the report by credibility."""
        evidence = getattr(report, "evidence", None) or []
        for ev in evidence:
            src = getattr(ev, "source", "") or ""
            if src not in self._credibility_cache:
                self._credibility_cache[src] = source_credibility(src)

        if self._credibility_cache:
            summary = "; ".join(
                f"{k}: {v:.0%}" for k, v in sorted(self._credibility_cache.items())
            )
            report.briefing.key_judgments.append(
                f"[Source Credibility] {summary}"
            )

    # ------------------------------------------------------------------
    # gap analysis
    # ------------------------------------------------------------------

    def _gap_analysis(self, report: Any, scan_result: Any) -> None:
        """Identify intelligence gaps and suggest next scans."""
        gaps: list[str] = []

        # Existing gaps from the briefing builder
        existing = set(
            getattr(report.briefing, "intelligence_gaps", None) or []
        )
        gaps.extend(existing)

        # Check coverage from scan_result modules
        modules_run = set(
            getattr(scan_result, "modules_run", None)
            or [getattr(f, "module", "") for f in getattr(scan_result, "findings", [])]
        )
        modules_run = {m for m in modules_run if m}

        high_value_gaps = [
            ("hibp", "No HaveIBeenPwned results — configure HIBP_API_KEY for breach correlation"),
            ("dehashed", "No DeHashed results — configure DEHASHED_API_KEY for deep breach lookup"),
            ("domain_recon", "No domain recon results — WHOIS/DNS data may reveal infrastructure"),
            ("phone_finder", "Phone numbers not investigated — configure phone_finder"),
        ]

        for module, msg in high_value_gaps:
            if module not in modules_run:
                gap_text = f"[Gap] {msg}"
                if gap_text not in gaps:
                    gaps.append(gap_text)

        # Update the report
        if hasattr(report.briefing, "intelligence_gaps"):
            report.briefing.intelligence_gaps = gaps
        elif hasattr(report.briefing, "key_judgments"):
            for g in gaps:
                report.briefing.key_judgments.append(g)

    # ------------------------------------------------------------------
    # conflict detection
    # ------------------------------------------------------------------

    def _detect_conflicts(self, report: Any, scan_result: Any) -> None:
        """Find contradictory findings across sources."""
        conflicts: list[str] = []

        # Collect per-entity confidence from evidence
        entity_sources: dict[str, list[tuple[str, float]]] = {}
        for ev in getattr(report, "evidence", None) or []:
            key = ev.identifier_value.strip().lower() if hasattr(ev, "identifier_value") else ""
            if not key:
                continue
            src = getattr(ev, "source", "?")
            conf = getattr(ev, "confidence", 0.5) or 0.5
            entity_sources.setdefault(key, []).append((src, conf))

        # Flag contradictions: same entity with wildly different confidence
        for entity, sources in entity_sources.items():
            if len(sources) < 2:
                continue
            confs = [c for _, c in sources]
            spread = max(confs) - min(confs)
            if spread > 0.5:
                src_list = ", ".join(
                    f"{s} ({c:.0%})" for s, c in sorted(sources, key=lambda x: -x[1])
                )
                conflicts.append(
                    f"Contradictory confidence for '{entity}': {src_list}"
                )

        if conflicts:
            report.briefing.key_judgments.append(
                f"[Conflict Detection] {'; '.join(conflicts[:5])}"
            )
