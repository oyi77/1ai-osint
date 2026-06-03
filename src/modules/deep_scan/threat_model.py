"""Predictive Threat Modeling — Phase 5 Pillar 6.

Scores subjects against known threat actor archetypes and predicts
probable next actions based on behavioral indicators.

Archetypes:
- FINANCIAL_FRAUD: credential trading, carding, money mule networks
- STATE_ACTOR: sophisticated APT patterns, infrastructure obfuscation
- INSIDER_THREAT: internal access abuse, data exfiltration patterns
- HACKTIVIST: public ideology, DDOS campaigns, defacement
- UNKNOWN: insufficient data to classify

All predictions are deterministic rule-based by default.
LLM enhancement available when OPENAI/OMNIROUTE API key is present.
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ThreatArchetype(str, Enum):
    FINANCIAL_FRAUD = "financial_fraud"
    STATE_ACTOR = "state_actor"
    INSIDER_THREAT = "insider_threat"
    HACKTIVIST = "hacktivist"
    UNKNOWN = "unknown"


class ThreatTrajectory(BaseModel):
    """Predicted threat trajectory for a subject."""

    most_likely_archetype: ThreatArchetype = ThreatArchetype.UNKNOWN
    archetype_scores: dict[str, float] = Field(default_factory=dict)
    predicted_next_actions: list[str] = Field(default_factory=list)
    high_risk_indicators: list[str] = Field(default_factory=list)
    confidence: str = "low"  # low | medium | high
    reasoning: str = ""
    analytical_method: str = "deterministic"


class PredictiveThreatModeler:
    """Classify subjects into threat archetypes and predict trajectories."""

    # Indicator weights per archetype
    _ARCHETYPE_RULES: dict[str, list[tuple[str, float]]] = {
        ThreatArchetype.FINANCIAL_FRAUD: [
            ("crypto_exposure", 0.30),
            ("breach_credential_count", 0.25),
            ("mixer_interaction", 0.20),
            ("multiple_payment_identities", 0.15),
            ("carding_keywords", 0.10),
        ],
        ThreatArchetype.STATE_ACTOR: [
            ("infrastructure_obfuscation", 0.30),
            ("opsec_advanced", 0.25),
            ("vpn_tor_usage", 0.20),
            ("minimal_social_footprint", 0.15),
            ("technical_sophistication", 0.10),
        ],
        ThreatArchetype.INSIDER_THREAT: [
            ("corporate_email_exposure", 0.30),
            ("github_sensitive_repos", 0.25),
            ("internal_credential_breach", 0.25),
            ("unusual_access_pattern", 0.20),
        ],
        ThreatArchetype.HACKTIVIST: [
            ("public_ideology_statements", 0.30),
            ("multiple_pseudonyms", 0.25),
            ("ddos_tool_exposure", 0.20),
            ("defacement_history", 0.15),
            ("dark_web_presence", 0.10),
        ],
    }

    _NEXT_ACTIONS: dict[str, list[str]] = {
        ThreatArchetype.FINANCIAL_FRAUD: [
            "Credential stuffing attacks against financial platforms",
            "Expansion to additional cryptocurrency mixing services",
            "Recruitment of money mule network members",
            "Exfiltration of additional payment card data",
        ],
        ThreatArchetype.STATE_ACTOR: [
            "Sustained long-term infrastructure establishment",
            "Spear-phishing campaign against high-value targets",
            "Lateral movement within compromised organizations",
            "Intelligence collection on identified targets of interest",
        ],
        ThreatArchetype.INSIDER_THREAT: [
            "Exfiltration of sensitive intellectual property",
            "Escalation of data access privileges",
            "Transfer of proprietary data to external storage",
            "Sale of access credentials to external threat actors",
        ],
        ThreatArchetype.HACKTIVIST: [
            "Coordinated social media campaign around identified cause",
            "DDoS attack against targeted organization",
            "Website defacement or data leak publication",
            "Recruitment of additional sympathizers",
        ],
        ThreatArchetype.UNKNOWN: [
            "Continued intelligence collection required",
            "Expand identifier discovery — additional pivots needed",
            "Cross-reference with known threat actor databases",
        ],
    }

    def _extract_indicators(self, report: Any) -> dict[str, float]:
        """Extract indicator signals from an IntelReport."""
        indicators: dict[str, float] = {}
        evidence = getattr(report, "evidence", []) or []
        risk = getattr(report, "risk", None)
        risk_score = getattr(risk, "score", 0.0) if risk else 0.0

        # Crypto exposure
        crypto_ev = [
            e for e in evidence if "crypto" in getattr(e, "source", "").lower()
        ]
        indicators["crypto_exposure"] = min(1.0, len(crypto_ev) * 0.2)

        # Breach credential count
        breach_ev = [
            e
            for e in evidence
            if getattr(e, "identifier_type", "") in ("email", "password", "hash")
        ]
        indicators["breach_credential_count"] = min(1.0, len(breach_ev) * 0.05)

        # Corporate email exposure
        email_ev = [e for e in evidence if getattr(e, "identifier_type", "") == "email"]
        corp_emails = [
            e
            for e in email_ev
            if any(
                corp in getattr(e, "identifier_value", "").lower()
                for corp in (".corp.", ".internal.", ".enterprise.")
            )
        ]
        indicators["corporate_email_exposure"] = 1.0 if corp_emails else 0.0

        # GitHub exposure
        git_ev = [e for e in evidence if "git" in getattr(e, "source", "").lower()]
        indicators["github_sensitive_repos"] = min(1.0, len(git_ev) * 0.3)

        # Social footprint size (inverse for state actor)
        social_ev = [
            e
            for e in evidence
            if getattr(e, "source", "") in ("social_osint", "sherlock", "maigret")
        ]
        indicators["minimal_social_footprint"] = max(0.0, 1.0 - len(social_ev) * 0.1)

        # Technical sophistication (high risk score proxy)
        indicators["technical_sophistication"] = min(1.0, risk_score)
        indicators["opsec_advanced"] = min(1.0, risk_score * 0.8)
        indicators["vpn_tor_usage"] = min(1.0, risk_score * 0.5)
        indicators["infrastructure_obfuscation"] = min(1.0, risk_score * 0.6)

        # Darknet presence
        dark_ev = [e for e in evidence if getattr(e, "source", "") == "darknet"]
        indicators["dark_web_presence"] = 1.0 if dark_ev else 0.0

        # Multiple identities
        username_ev = [
            e for e in evidence if getattr(e, "identifier_type", "") == "username"
        ]
        indicators["multiple_pseudonyms"] = min(1.0, len(username_ev) * 0.15)

        return indicators

    def score_archetypes(self, report: Any) -> dict[str, float]:
        """Score each archetype based on extracted indicators."""
        indicators = self._extract_indicators(report)
        scores: dict[str, float] = {}

        for archetype, rules in self._ARCHETYPE_RULES.items():
            score = 0.0
            for indicator_name, weight in rules:
                score += indicators.get(indicator_name, 0.0) * weight
            scores[archetype] = round(min(score, 1.0), 3)

        return scores

    def predict_trajectory(self, report: Any) -> ThreatTrajectory:
        """Predict the most likely threat trajectory for a subject."""
        scores = self.score_archetypes(report)
        evidence = getattr(report, "evidence", []) or []
        risk = getattr(report, "risk", None)
        risk_score = getattr(risk, "score", 0.0) if risk else 0.0

        # Find best archetype
        best_archetype = ThreatArchetype.UNKNOWN
        best_score = 0.0
        for archetype_str, score in scores.items():
            if score > best_score:
                best_score = score
                best_archetype = ThreatArchetype(archetype_str)

        # Confidence calibration
        if best_score >= 0.6:
            confidence = "high"
        elif best_score >= 0.35:
            confidence = "medium"
        else:
            confidence = "low"
            best_archetype = ThreatArchetype.UNKNOWN

        # High risk indicators
        high_risk = []
        if risk_score >= 0.7:
            high_risk.append(
                f"Overall risk score {risk_score:.2f} exceeds HIGH threshold"
            )
        indicators = self._extract_indicators(report)
        if indicators.get("dark_web_presence", 0) > 0:
            high_risk.append(
                "Confirmed darknet presence — active threat intelligence value"
            )
        if indicators.get("crypto_exposure", 0) >= 0.5:
            high_risk.append(
                "Significant cryptocurrency exposure — potential financial nexus"
            )
        if indicators.get("breach_credential_count", 0) >= 0.5:
            high_risk.append("High breach credential count — credential abuse likely")

        # Reasoning
        top_archetype_name = best_archetype.value.replace("_", " ").title()
        reasoning = (
            f"Archetype scoring places subject at {top_archetype_name} ({best_score:.1%}) with {confidence} confidence. "
            f"Total evidence: {len(evidence)} items. Risk score: {risk_score:.2f}. "
            f"{'Insufficient data for definitive classification.' if confidence == 'low' else 'Classification supported by evidence indicators.'}"
        )

        return ThreatTrajectory(
            most_likely_archetype=best_archetype,
            archetype_scores=scores,
            predicted_next_actions=self._NEXT_ACTIONS.get(best_archetype, [])[:3],
            high_risk_indicators=high_risk,
            confidence=confidence,
            reasoning=reasoning,
            analytical_method="deterministic",
        )

    async def llm_enhanced_prediction(
        self,
        report: Any,
        trajectory: ThreatTrajectory,
    ) -> ThreatTrajectory:
        """Enhance trajectory with LLM reasoning if API key is available."""
        api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get(
            "OMNIROUTE_API_KEY"
        )
        if not api_key:
            return trajectory

        try:
            import httpx
            import json

            base_url = os.environ.get("OMNIROUTE_BASE_URL", "https://api.openai.com/v1")
            model = os.environ.get("OMNIROUTE_MODEL", "gpt-4o-mini")
            prompt = (
                f"Threat archetype: {trajectory.most_likely_archetype.value}\n"
                f"Score: {trajectory.archetype_scores}\n"
                f"Risk indicators: {trajectory.high_risk_indicators}\n\n"
                "Provide 2-3 specific predicted next actions for this threat actor, "
                "and a one-sentence reasoning. Return JSON: {next_actions: [...], reasoning: '...'}"
            )
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": {"type": "json_object"},
                    },
                )
                data = json.loads(resp.json()["choices"][0]["message"]["content"])
            trajectory.predicted_next_actions = data.get(
                "next_actions", trajectory.predicted_next_actions
            )
            trajectory.reasoning = data.get("reasoning", trajectory.reasoning)
            trajectory.analytical_method = "llm"
        except Exception as exc:
            logger.warning("LLM threat enhancement failed: %s", exc)

        return trajectory
