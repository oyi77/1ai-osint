"""Delta briefing — compare two intel reports with semantic analysis.

Provides ``compute_intel_delta()`` for backward compatibility and the
richer ``DeltaAnalyzer`` class for AI-powered change analysis,
severity scoring, and timeline reconstruction.
"""

from __future__ import annotations

import logging
from typing import Any

from src.modules.monitoring.models import (
    ChangeEvent,
    ChangeSeverity,
    ChangeType,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Backward-compatible function (unchanged API)
# ------------------------------------------------------------------


def compute_intel_delta(previous: dict, current: dict) -> dict[str, Any]:
    """Return new evidence handles, emails, and breach count delta.

    This is the legacy function — for richer output use ``DeltaAnalyzer``.
    """
    prev_ev = {e.get("identifier_value") for e in previous.get("evidence", [])}
    curr_ev = current.get("evidence", [])
    new_evidence = [e for e in curr_ev if e.get("identifier_value") not in prev_ev]
    prev_brief = previous.get("briefing", {})
    curr_brief = current.get("briefing", {})
    prev_emails = set(prev_brief.get("subject", {}).get("emails", []))
    curr_emails = set(curr_brief.get("subject", {}).get("emails", []))
    return {
        "new_evidence_count": len(new_evidence),
        "new_evidence": new_evidence[:50],
        "new_emails": sorted(curr_emails - prev_emails),
        "new_handles": sorted(
            set(curr_brief.get("subject", {}).get("known_handles", []))
            - set(prev_brief.get("subject", {}).get("known_handles", []))
        ),
        "breach_delta": len(curr_brief.get("breach_records", [])) - len(prev_brief.get("breach_records", [])),
    }


# ------------------------------------------------------------------
# Severity scoring
# ------------------------------------------------------------------

_CHANGE_TYPE_SEVERITY_MAP: dict[ChangeType, ChangeSeverity] = {
    ChangeType.NEW_BREACH: ChangeSeverity.HIGH,
    ChangeType.RISK_SCORE_CHANGE: ChangeSeverity.HIGH,
    ChangeType.NEW_EMAIL: ChangeSeverity.MEDIUM,
    ChangeType.NEW_PHONE: ChangeSeverity.MEDIUM,
    ChangeType.NEW_HANDLE: ChangeSeverity.LOW,
    ChangeType.NEW_DOMAIN: ChangeSeverity.LOW,
    ChangeType.NEW_CRYPTO_ADDRESS: ChangeSeverity.LOW,
    ChangeType.NEW_SOCIAL_ACCOUNT: ChangeSeverity.LOW,
    ChangeType.FIELD_CHANGE: ChangeSeverity.LOW,
    ChangeType.ATTRIBUTE_CHANGE: ChangeSeverity.INFO,
    ChangeType.SOURCE_DISAPPEARED: ChangeSeverity.INFO,
    ChangeType.CONFIDENCE_CHANGE: ChangeSeverity.INFO,
}


def _default_severity(change_type: ChangeType) -> ChangeSeverity:
    return _CHANGE_TYPE_SEVERITY_MAP.get(change_type, ChangeSeverity.INFO)


# ------------------------------------------------------------------
# DeltaAnalyzer
# ------------------------------------------------------------------


class DeltaAnalyzer:
    """Rich semantic delta analysis between two intel reports.

    Compared to the legacy ``compute_intel_delta()``, this class:

    * Produces typed ``ChangeEvent`` objects (not a plain dict).
    * Computes severity per change based on type + context heuristics.
    * Builds a chronological timeline of changes.
    * Provides an AI-powered narrative summary (when AI is available).
    * Scores the overall risk impact of the delta.
    """

    def __init__(self, enable_ai: bool = False):
        self.enable_ai = enable_ai

    # ------------------------------------------------------------------
    # main analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        previous: dict[str, Any] | None,
        current: dict[str, Any],
        *,
        target: str | None = None,
    ) -> DeltaResult:
        """Full delta analysis between two intel snapshots.

        Parameters
        ----------
        previous : dict or None
            Previous intel snapshot.  ``None`` means first scan.
        current : dict
            Current intel snapshot.
        target : str, optional
            Name of the target entity.

        Returns
        -------
        DeltaResult

        """
        from src.modules.monitoring.change_detector import ChangeDetector

        detector = ChangeDetector()
        events = detector.detect_changes(previous, current, target=target)

        # Severity pass
        for ev in events:
            if ev.severity == ChangeSeverity.INFO:
                ev.severity = _default_severity(ev.change_type)

        # Delta dict (backward-compat shape)
        delta_summary = self._summarise(previous, current, events)

        # Timeline
        timeline = sorted(events, key=lambda e: e.timestamp)

        # AI narrative
        narrative: str | None = None
        if self.enable_ai and events:
            narrative = self._ai_narrative(previous, current, events)

        # Impact score
        impact = self._compute_impact(events)

        return DeltaResult(
            events=events,
            delta_summary=delta_summary,
            timeline=timeline,
            ai_narrative=narrative,
            impact_score=impact,
            event_count=len(events),
            critical_count=sum(1 for e in events if e.severity == ChangeSeverity.CRITICAL),
            high_count=sum(1 for e in events if e.severity == ChangeSeverity.HIGH),
            medium_count=sum(1 for e in events if e.severity == ChangeSeverity.MEDIUM),
        )

    # ------------------------------------------------------------------
    # summarise
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise(
        previous: dict[str, Any] | None,
        current: dict[str, Any],
        events: list[ChangeEvent],
    ) -> dict[str, Any]:
        """Build a simple summary dict (similar to legacy ``compute_intel_delta``)."""
        prev_brief = previous.get("briefing", {}) if previous else {}
        curr_brief = current.get("briefing", {})

        curr_ev = current.get("evidence", [])
        prev_ev_set = {e.get("identifier_value") for e in previous.get("evidence", [])} if previous else set()
        new_ev = [e for e in curr_ev if e.get("identifier_value") not in prev_ev_set]

        return {
            "new_evidence_count": len(new_ev),
            "new_evidence": new_ev[:50],
            "new_emails": sorted(
                set(curr_brief.get("subject", {}).get("emails", []))
                - (set(prev_brief.get("subject", {}).get("emails", [])) if previous else set())
            ),
            "new_handles": sorted(
                set(curr_brief.get("subject", {}).get("known_handles", []))
                - (set(prev_brief.get("subject", {}).get("known_handles", [])) if previous else set())
            ),
            "breach_delta": len(curr_brief.get("breach_records", []))
            - (len(prev_brief.get("breach_records", [])) if previous else 0),
            "event_count": len(events),
            "high_severity_count": sum(
                1 for e in events if e.severity in (ChangeSeverity.HIGH, ChangeSeverity.CRITICAL)
            ),
        }

    # ------------------------------------------------------------------
    # severity / impact
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_impact(events: list[ChangeEvent]) -> float:
        """Compute a numeric impact score (0.0 = none, 1.0 = critical blast)."""
        weights = {
            ChangeSeverity.CRITICAL: 1.0,
            ChangeSeverity.HIGH: 0.7,
            ChangeSeverity.MEDIUM: 0.4,
            ChangeSeverity.LOW: 0.15,
            ChangeSeverity.INFO: 0.0,
        }
        if not events:
            return 0.0
        raw = sum(weights.get(e.severity, 0.0) for e in events)
        # Normalise to [0, 1] with diminishing returns for many low-sev events
        score = 1.0 - (1.0 / (1.0 + raw))
        return round(score, 3)

    # ------------------------------------------------------------------
    # AI narrative
    # ------------------------------------------------------------------

    def _ai_narrative(
        self,
        previous: dict[str, Any] | None,
        current: dict[str, Any],
        events: list[ChangeEvent],
    ) -> str | None:
        """Attempt an LLM-generated narrative of what changed and why it matters.

        Falls back to a rule-based summary if AI is unavailable.
        """
        try:
            from src.ai.orchestrator import AnalysisOrchestrator
            from src.core.config import Settings

            settings = Settings()
            if not settings.effective_openai_api_key:
                return None

            import asyncio

            prompt = f"Delta analysis for '{events[0].target}' — {len(events)} change event(s):\n"
            for ev in events:
                prompt += (
                    f"- [{ev.severity.value.upper()}] {ev.change_type.value}: "
                    f"{ev.description} (conf={ev.confidence})\n"
                )
            prompt += "\nSummarise what changed, why it matters operationally, and the risk impact in 2-3 sentences."

            orchestrator = AnalysisOrchestrator()
            narrative = asyncio.run(
                orchestrator._call_llm(prompt)  # noqa: SLF001 — internal API
            )
            if narrative and isinstance(narrative, str):
                return narrative.strip()
        except Exception as exc:
            logger.debug("AI narrative skipped: %s", exc)

        # Fallback rule-based summary
        return self._rule_narrative(events)

    @staticmethod
    def _rule_narrative(events: list[ChangeEvent]) -> str:
        """Generate a human-readable summary without AI."""
        high = [e for e in events if e.severity in (ChangeSeverity.HIGH, ChangeSeverity.CRITICAL)]
        medium = [e for e in events if e.severity == ChangeSeverity.MEDIUM]
        parts: list[str] = []
        if high:
            parts.append(f"{len(high)} high-severity change(s): " + "; ".join(e.description for e in high[:3]))
        if medium:
            parts.append(f"{len(medium)} medium-severity change(s): " + "; ".join(e.description for e in medium[:3]))
        if not parts:
            parts.append("No significant changes detected in this scan cycle.")
        return " | ".join(parts)


# ------------------------------------------------------------------
# Result container
# ------------------------------------------------------------------


class DeltaResult:
    """Structured output of a delta analysis."""

    def __init__(
        self,
        *,
        events: list[ChangeEvent],
        delta_summary: dict[str, Any],
        timeline: list[ChangeEvent],
        ai_narrative: str | None,
        impact_score: float,
        event_count: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
    ):
        self.events = events
        self.delta_summary = delta_summary
        self.timeline = timeline
        self.ai_narrative = ai_narrative
        self.impact_score = impact_score
        self.event_count = event_count
        self.critical_count = critical_count
        self.high_count = high_count
        self.medium_count = medium_count

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict."""
        return {
            "event_count": self.event_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "impact_score": self.impact_score,
            "events": [e.model_dump(mode="json") for e in self.events],
            "delta_summary": self.delta_summary,
            "timeline": [e.model_dump(mode="json") for e in self.timeline],
            "ai_narrative": self.ai_narrative,
        }

    def markdown_report(self) -> str:
        """Render as a markdown delta briefing."""
        lines = [
            "# Delta Briefing",
            f"**Impact Score:** {self.impact_score}",
            f"**Events:** {self.event_count} (critical={self.critical_count}, high={self.high_count}, medium={self.medium_count})",
            "",
        ]
        if self.ai_narrative:
            lines.append(f"> {self.ai_narrative}")
            lines.append("")
        lines.append("## Timeline")
        for ev in self.timeline:
            lines.append(f"- **[{ev.severity.value.upper()}]** {ev.change_type.value}: " f"{ev.description}")
        return "\n".join(lines)
