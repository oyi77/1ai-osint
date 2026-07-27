"""Adversarial AI Analyst — CIA-style Red Team / Blue Team intelligence analysis.

Implements a multi-pass analytical cycle:
1. Collection Summary — what was found
2. Red Team Analysis — adversarial: treat subject as threat actor
3. Blue Team Analysis — defensive: assume innocence, test against evidence
4. Gap Assessment — what's missing that would change the assessment
5. Confidence Calibration — explicit probabilistic statements
6. BLUF++ — enriched executive summary
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CIAAnalysis(BaseModel):
    """Full adversarial intelligence analysis result."""

    red_team_narrative: str = ""
    blue_team_narrative: str = ""
    intelligence_gaps: list[str] = Field(default_factory=list)
    calibrated_confidences: dict[str, float] = Field(default_factory=dict)
    bluf_plus: str = ""
    classification_line: str = "UNCLASSIFIED // OSINT // LAWFUL USE ONLY"
    analytical_method: str = "deterministic"  # "deterministic" or "llm"


class AdversarialAnalyst:
    """Dual Red/Blue Team intelligence analyst.

    Uses LLM when OPENAI_API_KEY or OMNIROUTE_API_KEY is set.
    Falls back to deterministic rule-based analysis otherwise.
    """

    def __init__(self) -> None:
        self._llm_available = self._check_llm_available()

    @staticmethod
    def _check_llm_available() -> bool:
        import os

        return bool(
            os.environ.get("OPENAI_API_KEY") or os.environ.get("OMNIROUTE_API_KEY")
        )

    async def run_analysis(self, report: Any) -> CIAAnalysis:
        """Run full adversarial analysis on an IntelReport."""
        evidence_summary = self._summarize_evidence(report)
        if self._llm_available:
            try:
                return await self._llm_analysis(report, evidence_summary)
            except Exception as exc:
                logger.warning(
                    "LLM analysis failed, falling back to deterministic: %s", exc
                )
        return self._deterministic_analysis(report, evidence_summary)

    def _summarize_evidence(self, report: Any) -> str:
        """Summarize evidence for prompt or deterministic processing."""
        lines = []
        target = getattr(report, "target", "Unknown")
        lines.append(f"Target: {target}")
        evidence = getattr(report, "evidence", []) or []
        lines.append(f"Evidence items: {len(evidence)}")
        sources = list({e.source for e in evidence if hasattr(e, "source")})
        lines.append(f"Sources: {', '.join(sources[:10])}")
        risk = getattr(report, "risk", None)
        if risk:
            lines.append(f"Risk level: {getattr(risk, 'level', 'unknown')}")
            lines.append(f"Risk score: {getattr(risk, 'score', 0.0):.2f}")
        breaches = [
            e
            for e in evidence
            if getattr(e, "identifier_type", "") in ("email", "password")
        ]
        lines.append(f"Breach-related evidence: {len(breaches)}")
        crypto = [e for e in evidence if "crypto" in getattr(e, "source", "").lower()]
        lines.append(f"Crypto-related evidence: {len(crypto)}")
        return "\n".join(lines)

    def _deterministic_analysis(
        self, report: Any, evidence_summary: str
    ) -> CIAAnalysis:
        """Rule-based analysis without LLM."""
        risk = getattr(report, "risk", None)
        risk_score = getattr(risk, "score", 0.0) if risk else 0.0
        risk_level = str(getattr(risk, "level", "none")).lower()
        evidence = getattr(report, "evidence", []) or []
        target = getattr(report, "target", "Unknown")
        breach_count = len(
            [
                e
                for e in evidence
                if getattr(e, "identifier_type", "") in ("email", "password", "hash")
            ]
        )
        crypto_count = len(
            [e for e in evidence if "crypto" in getattr(e, "source", "").lower()]
        )

        # Red Team
        red_indicators = []
        if risk_score >= 0.7:
            red_indicators.append(
                f"HIGH risk score ({risk_score:.2f}) consistent with active threat actor"
            )
        if breach_count > 5:
            red_indicators.append(
                f"{breach_count} breach exposures suggest credential recycling or exfiltration activity"
            )
        if crypto_count > 0:
            red_indicators.append(
                f"{crypto_count} cryptocurrency transaction links — potential money movement or sanctions evasion"
            )
        if not red_indicators:
            red_indicators.append(
                "No high-confidence adversarial indicators identified — subject may be low-priority or well-masked"
            )
        red_narrative = (
            f"RED TEAM ASSESSMENT for {target}: "
            + " ".join(red_indicators)
            + " Recommend continued collection to confirm or rule out threat actor hypothesis."
        )

        # Blue Team
        blue_indicators = []
        if risk_score < 0.3:
            blue_indicators.append(
                "Low overall risk score consistent with ordinary digital footprint"
            )
        if breach_count <= 2:
            blue_indicators.append(
                "Minimal breach exposure — within normal range for average internet user"
            )
        if not blue_indicators:
            blue_indicators.append(
                "Evidence is ambiguous; benign explanation cannot be ruled out"
            )
        blue_narrative = (
            f"BLUE TEAM ASSESSMENT for {target}: "
            + " ".join(blue_indicators)
            + " Innocent hypothesis supported unless corroborating adversarial evidence emerges."
        )

        # Gaps
        gaps = []
        modules_run = getattr(report, "modules_run", []) or []
        if "phone_finder" not in modules_run:
            gaps.append(
                "Phone number linkage not attempted — may reveal additional identity nodes"
            )
        if "gitleaks" not in modules_run:
            gaps.append(
                "Code repository analysis not performed — could expose credentials or operational code"
            )
        if crypto_count == 0:
            gaps.append(
                "No cryptocurrency exposure identified — check blockchain directly if financial nexus suspected"
            )
        gaps.append(
            "Physical world correlates (travel records, public registrations) not available via OSINT"
        )

        # Confidence
        confidences: dict[str, float] = {
            "identity_confirmed": min(0.95, 0.3 + (len(evidence) * 0.01)),
            "adversarial_hypothesis": min(0.90, risk_score),
            "data_currency": 0.7,
        }

        # BLUF++
        bluf = (
            f"SUBJECT: {target} | RISK: {risk_level.upper()} ({risk_score:.2f}) | "
            f"EVIDENCE: {len(evidence)} items across {len(set(getattr(e, 'source', '') for e in evidence))} sources | "
            f"ASSESSMENT: {'HIGH PRIORITY — adversarial indicators present' if risk_score >= 0.7 else 'MONITOR — insufficient evidence for definitive judgment'} | "
            f"GAPS: {len(gaps)} identified"
        )

        return CIAAnalysis(
            red_team_narrative=red_narrative,
            blue_team_narrative=blue_narrative,
            intelligence_gaps=gaps,
            calibrated_confidences=confidences,
            bluf_plus=bluf,
            analytical_method="deterministic",
        )

    async def _llm_analysis(self, report: Any, evidence_summary: str) -> CIAAnalysis:
        """LLM-enhanced analysis via OmniRouteClient."""
        import json

        from src.ai.omniroute_client import OmniRouteClient

        client = OmniRouteClient()
        system = (
            "You are a senior intelligence analyst trained in CIA analytical tradecraft. "
            "You produce rigorous, evidence-cited intelligence assessments using structured analytical techniques. "
            "Format: JSON only, no extra text."
        )
        user_msg = f"""Analyze the following OSINT evidence summary and produce a dual Red/Blue team assessment.

Evidence Summary:
{evidence_summary}

Return JSON with keys:
- red_team_narrative: adversarial hypothesis narrative (2-3 sentences)
- blue_team_narrative: benign hypothesis narrative (2-3 sentences)
- intelligence_gaps: list of 3-5 key collection gaps
- calibrated_confidences: dict with keys identity_confirmed, adversarial_hypothesis, data_currency (floats 0-1)
- bluf_plus: one-sentence executive summary"""

        data = await client.async_chat(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            response_format={"type": "json_object"},
        )
        parsed = json.loads(data)

        return CIAAnalysis(
            red_team_narrative=parsed.get("red_team_narrative", ""),
            blue_team_narrative=parsed.get("blue_team_narrative", ""),
            intelligence_gaps=parsed.get("intelligence_gaps", []),
            calibrated_confidences=parsed.get("calibrated_confidences", {}),
            bluf_plus=parsed.get("bluf_plus", ""),
            analytical_method="llm",
        )

    async def red_team_pass(self, evidence_summary: str) -> str:
        """Single red-team reasoning pass (standalone)."""
        return f"RED TEAM: Analyzing evidence for adversarial indicators — {evidence_summary[:100]}..."

    async def blue_team_pass(self, evidence_summary: str) -> str:
        """Single blue-team reasoning pass (standalone)."""
        return f"BLUE TEAM: Testing benign hypothesis against evidence — {evidence_summary[:100]}..."

    async def gap_assessment(self, report: Any) -> list[str]:
        """Return collection gaps for this report."""
        analysis = await self.run_analysis(report)
        return analysis.intelligence_gaps

    def calibrate_confidence(self, report: Any) -> dict[str, float]:
        """Return calibrated confidence scores (synchronous wrapper)."""
        evidence = getattr(report, "evidence", []) or []
        risk = getattr(report, "risk", None)
        risk_score = getattr(risk, "score", 0.0) if risk else 0.0
        return {
            "identity_confirmed": min(0.95, 0.3 + len(evidence) * 0.01),
            "adversarial_hypothesis": min(0.90, risk_score),
            "data_currency": 0.7,
        }
