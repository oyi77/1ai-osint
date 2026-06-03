"""Counterintelligence & Legend Detection — Phase 5 Pillar 7.

Detects fabricated identities (legends), assesses operational security (OPSEC)
sophistication, and flags deception patterns in OSINT evidence.

A 'legend' is an intelligence tradecraft term for a fabricated identity
created to deceive investigators or establish false cover.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class OPSECLevel(str, Enum):
    NONE = "none"  # No apparent security awareness
    BASIC = "basic"  # Some privacy behaviors
    INTERMEDIATE = "intermediate"  # VPN usage, pseudonym discipline
    ADVANCED = "advanced"  # Tor, compartmentalization, legend use


class LegendIndicator(BaseModel):
    """A single indicator suggesting a fabricated identity."""

    rule: str
    description: str
    severity: str = "low"  # low | medium | high
    triggered: bool = False
    evidence: list[str] = Field(default_factory=list)


class CounterIntelAssessment(BaseModel):
    """Full counterintelligence assessment for a subject."""

    is_likely_legend: bool = False
    legend_confidence: float = 0.0  # [0.0, 1.0]
    legend_indicators: list[LegendIndicator] = Field(default_factory=list)
    opsec_level: OPSECLevel = OPSECLevel.NONE
    deception_indicators: list[str] = Field(default_factory=list)
    recommended_ci_actions: list[str] = Field(default_factory=list)
    assessment_notes: str = ""


class CounterIntelAnalyzer:
    """Analyze OSINT reports for legend and deception patterns."""

    # Legend detection rules
    _LEGEND_RULES: list[dict] = [
        {
            "rule": "FRESH_ACCOUNT_HIGH_ACTIVITY",
            "description": "Account created within last 30 days but shows unusual breadth of activity",
            "severity": "high",
        },
        {
            "rule": "USERNAME_PATTERN_MATCH",
            "description": "Username follows common legend naming pattern (e.g., firstname+numbers, random word combos)",
            "severity": "medium",
        },
        {
            "rule": "NO_HISTORICAL_FOOTPRINT",
            "description": "Subject has no digital footprint predating 12 months",
            "severity": "high",
        },
        {
            "rule": "INCONSISTENT_LOCATION_CLAIMS",
            "description": "Stated location inconsistent with IP geolocation or timezone patterns",
            "severity": "high",
        },
        {
            "rule": "TEMPLATED_BIO",
            "description": "Profile bio appears templated or AI-generated (very short, generic, or formulaic)",
            "severity": "medium",
        },
        {
            "rule": "CROSS_PLATFORM_CREATION_DATE_MISMATCH",
            "description": "Multiple platform accounts created within same narrow time window — possible bulk legend creation",
            "severity": "medium",
        },
        {
            "rule": "NO_BREACH_EXPOSURE",
            "description": "Zero breach exposure despite claimed long tenure — may indicate recently created identity",
            "severity": "low",
        },
        {
            "rule": "PERFECT_OPSEC_CONSISTENCY",
            "description": "Suspiciously consistent OPSEC across all platforms — may indicate trained operator",
            "severity": "medium",
        },
    ]

    # OPSEC signals
    _OPSEC_SIGNALS = {
        "vpn_keywords": ["vpn", "mullvad", "proton", "nordvpn", "expressvpn"],
        "tor_keywords": ["tor", ".onion", "tails", "whonix"],
        "privacy_email": [
            "protonmail",
            "tutanota",
            "guerrilla",
            "temp-mail",
            "mailinator",
            "dispostable",
        ],
        "privacy_os": ["tails", "qubes", "whonix", "kali"],
        "opsec_tools": ["pgp", "gpg", "signal", "wickr", "keybase"],
    }

    def assess_legend_probability(self, report: Any) -> CounterIntelAssessment:
        """Run full counterintelligence assessment."""
        assessment = CounterIntelAssessment()
        evidence = getattr(report, "evidence", []) or []

        # Run each legend indicator rule
        legend_score = 0.0
        for rule_def in self._LEGEND_RULES:
            indicator = LegendIndicator(
                rule=rule_def["rule"],
                description=rule_def["description"],
                severity=rule_def["severity"],
            )
            # Check each rule
            triggered, ev = self._check_rule(rule_def["rule"], report, evidence)
            indicator.triggered = triggered
            indicator.evidence = ev
            assessment.legend_indicators.append(indicator)

            if triggered:
                weight = {"high": 0.3, "medium": 0.15, "low": 0.05}.get(
                    rule_def["severity"], 0.05
                )
                legend_score += weight

        assessment.legend_confidence = round(min(legend_score, 1.0), 3)
        assessment.is_likely_legend = legend_score >= 0.45

        # OPSEC assessment
        assessment.opsec_level = self.score_opsec_level(report)

        # Deception indicators
        assessment.deception_indicators = self.detect_deception_patterns(report)

        # Recommended CI actions
        assessment.recommended_ci_actions = self._build_recommendations(assessment)

        # Notes
        triggered_count = sum(1 for i in assessment.legend_indicators if i.triggered)
        assessment.assessment_notes = (
            f"{triggered_count}/{len(self._LEGEND_RULES)} legend indicators triggered. "
            f"OPSEC level: {assessment.opsec_level.value}. "
            f"Legend confidence: {assessment.legend_confidence:.1%}."
        )

        return assessment

    def _check_rule(
        self, rule: str, report: Any, evidence: list
    ) -> tuple[bool, list[str]]:
        """Check a specific legend rule. Returns (triggered, evidence_notes)."""
        ev_notes = []

        if rule == "NO_BREACH_EXPOSURE":
            breach_ev = [
                e
                for e in evidence
                if getattr(e, "identifier_type", "") in ("email", "password", "hash")
            ]
            if not breach_ev:
                ev_notes.append("Zero breach records found")
                return True, ev_notes

        elif rule == "NO_HISTORICAL_FOOTPRINT":
            timeline = getattr(report, "timeline", []) or []
            if not timeline:
                ev_notes.append("No temporal evidence found")
                return True, ev_notes

        elif rule == "USERNAME_PATTERN_MATCH":
            identifiers = getattr(report, "identifiers", []) or []
            for ident in identifiers:
                val = getattr(ident, "value", "")
                if (
                    getattr(ident, "id_type", None)
                    and str(getattr(ident, "id_type", "")) == "IdentifierType.USERNAME"
                ):
                    # Pattern: word + 3-5 digits
                    if re.match(r"^[a-z]+\d{3,5}$", val.lower()):
                        ev_notes.append(
                            f"Username '{val}' matches common legend pattern"
                        )
                        return True, ev_notes

        elif rule == "PERFECT_OPSEC_CONSISTENCY":
            # If OPSEC is advanced across many sources — flag as suspicious
            privacy_hits = self._count_privacy_signals(evidence)
            if privacy_hits >= 3:
                ev_notes.append(
                    f"Consistent privacy tooling across {privacy_hits} evidence signals"
                )
                return True, ev_notes

        return False, []

    def _count_privacy_signals(self, evidence: list) -> int:
        """Count how many privacy/OPSEC signals appear in evidence."""
        count = 0
        all_text = " ".join(
            str(getattr(e, "identifier_value", "")) + " " + str(getattr(e, "notes", ""))
            for e in evidence
        ).lower()
        for category, keywords in self._OPSEC_SIGNALS.items():
            if any(kw in all_text for kw in keywords):
                count += 1
        return count

    def score_opsec_level(self, report: Any) -> OPSECLevel:
        """Score the subject's operational security sophistication."""
        evidence = getattr(report, "evidence", []) or []
        privacy_count = self._count_privacy_signals(evidence)

        # Check for Tor/darknet usage
        darknet_ev = [e for e in evidence if getattr(e, "source", "") == "darknet"]
        uses_tor = bool(darknet_ev) or any(
            "tor" in str(getattr(e, "identifier_value", "")).lower()
            or ".onion" in str(getattr(e, "identifier_value", "")).lower()
            for e in evidence
        )

        if uses_tor or privacy_count >= 3:
            return OPSECLevel.ADVANCED
        elif privacy_count >= 2:
            return OPSECLevel.INTERMEDIATE
        elif privacy_count >= 1:
            return OPSECLevel.BASIC
        else:
            return OPSECLevel.NONE

    def detect_deception_patterns(self, report: Any) -> list[str]:
        """Identify specific deception patterns in evidence."""
        indicators = []
        evidence = getattr(report, "evidence", []) or []
        identifiers = getattr(report, "identifiers", []) or []

        # Contradictory location signals
        locations = set()
        for ev in evidence:
            raw = getattr(ev, "raw_data", {}) or {}
            for key in ("city", "country", "region"):
                if raw.get(key):
                    locations.add(str(raw[key]))
        if len(locations) >= 4:
            indicators.append(
                f"Contradictory location signals across {len(locations)} distinct locations"
            )

        # Multiple disconnected identities
        emails = [
            i
            for i in identifiers
            if str(getattr(i, "id_type", "")) == "IdentifierType.EMAIL"
        ]
        if len(emails) >= 5:
            indicators.append(
                f"{len(emails)} distinct email addresses — possible multiple simultaneous legends"
            )

        # Suspiciously clean digital profile
        if not evidence:
            indicators.append(
                "Zero evidence found — subject may have actively scrubbed digital footprint"
            )

        # AI-generated content signals (placeholder — would require NLP in production)
        # For now, flag very short bio texts
        for ev in evidence:
            raw = getattr(ev, "raw_data", {}) or {}
            bio = str(raw.get("bio", "") or raw.get("description", "") or "")
            if 0 < len(bio) < 20:
                indicators.append(
                    f"Suspiciously minimal profile bio ({len(bio)} chars) — possible synthetic identity"
                )
                break

        return indicators

    def _build_recommendations(self, assessment: CounterIntelAssessment) -> list[str]:
        """Build recommended counterintelligence actions."""
        recs = []
        if assessment.is_likely_legend:
            recs.append(
                "High legend probability — request independent verification of claimed identity"
            )
            recs.append(
                "Cross-reference creation dates with known legend factories or automated account providers"
            )
        if assessment.opsec_level in (OPSECLevel.INTERMEDIATE, OPSECLevel.ADVANCED):
            recs.append(
                f"OPSEC level {assessment.opsec_level.value} — standard collection approaches may be compromised"
            )
            recs.append("Consider passive collection only to avoid alerting subject")
        if assessment.deception_indicators:
            recs.append(
                f"{len(assessment.deception_indicators)} deception pattern(s) found — treat all self-reported data as suspect"
            )
        if not recs:
            recs.append(
                "No significant counterintelligence concerns — standard collection protocols apply"
            )
        return recs
