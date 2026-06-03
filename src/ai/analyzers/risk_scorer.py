"""Aggregate risk scoring across all OSINT module outputs."""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from src.core.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# Default weights per module (higher = more influence on final score)
_DEFAULT_MODULE_WEIGHTS: dict[str, float] = {
    "data_leaks": 1.0,
    "gitleaks": 0.9,
    "identity_tracking": 0.8,
    "people_finder": 0.7,
    "phone_finder": 0.6,
    "crypto": 0.5,
}

# Default weights per severity level
_SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.CRITICAL.value: 1.0,
    Severity.HIGH.value: 0.75,
    Severity.MEDIUM.value: 0.5,
    Severity.LOW.value: 0.25,
    Severity.INFO.value: 0.1,
}

# Category definitions for risk breakdown
_RISK_CATEGORIES: dict[str, list[str]] = {
    "data_exposure": ["data_leaks", "gitleaks"],
    "identity": ["identity_tracking", "people_finder", "phone_finder"],
    "crypto": ["crypto"],
}


@dataclass
class RiskBreakdown:
    """Risk score broken down by category."""

    category: str
    score: float
    finding_count: int
    top_severity: Optional[str] = None
    details: list[str] = field(default_factory=list)


@dataclass
class RiskScore:
    """Complete risk assessment result."""

    overall_score: float  # 0.0 to 100.0
    risk_level: str  # critical, high, medium, low, minimal
    breakdowns: list[RiskBreakdown] = field(default_factory=list)
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    modules_contributed: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_level": self.risk_level,
            "breakdowns": [
                {
                    "category": b.category,
                    "score": round(b.score, 2),
                    "finding_count": b.finding_count,
                    "top_severity": b.top_severity,
                    "details": b.details,
                }
                for b in self.breakdowns
            ],
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "modules_contributed": self.modules_contributed,
            "summary": self.summary,
        }


class RiskScorer:
    """Aggregate risk scoring across all module outputs."""

    def __init__(
        self,
        module_weights: Optional[dict[str, float]] = None,
        severity_weights: Optional[dict[str, float]] = None,
    ):
        self._module_weights = module_weights or dict(_DEFAULT_MODULE_WEIGHTS)
        self._severity_weights = severity_weights or dict(_SEVERITY_WEIGHTS)

    def score(self, scan_results: list[ScanResult]) -> RiskScore:
        """
        Compute aggregate risk score from multiple ScanResults.

        Args:
            scan_results: List of ScanResult objects from various modules.
        Returns:
            RiskScore with overall score and per-category breakdowns.
        """
        if not scan_results:
            return RiskScore(
                overall_score=0.0,
                risk_level="minimal",
                summary="No scan results to score",
            )

        all_findings: list[Finding] = []
        modules_seen: set[str] = set()

        for result in scan_results:
            all_findings.extend(result.findings)
            modules_seen.add(result.module)

        # Compute per-category breakdowns
        breakdowns: list[RiskBreakdown] = []
        for category, category_modules in _RISK_CATEGORIES.items():
            category_findings = [
                f for f in all_findings if f.module in category_modules
            ]
            if category_findings:
                breakdowns.append(self._score_category(category, category_findings))

        # Compute overall score as weighted average of category scores
        if breakdowns:
            total_weight = sum(
                self._module_weight(b.category) * b.finding_count for b in breakdowns
            )
            if total_weight > 0:
                overall = (
                    sum(
                        b.score * self._module_weight(b.category) * b.finding_count
                        for b in breakdowns
                    )
                    / total_weight
                )
            else:
                overall = 0.0
        else:
            overall = 0.0

        # Boost for critical findings
        critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        if critical_count > 0:
            overall = min(100.0, overall + critical_count * 5.0)

        risk_level = self._score_to_level(overall)

        return RiskScore(
            overall_score=overall,
            risk_level=risk_level,
            breakdowns=breakdowns,
            total_findings=len(all_findings),
            critical_findings=critical_count,
            high_findings=high_count,
            modules_contributed=sorted(modules_seen),
            summary=self._build_summary(overall, risk_level, all_findings, breakdowns),
        )

    def score_single(self, scan_result: ScanResult) -> RiskScore:
        """Score a single ScanResult."""
        return self.score([scan_result])

    def _score_category(self, category: str, findings: list[Finding]) -> RiskBreakdown:
        """Score a single risk category."""
        if not findings:
            return RiskBreakdown(category=category, score=0.0, finding_count=0)

        weighted_sum = 0.0
        weight_total = 0.0
        top_severity_val = 0.0
        top_severity_name: Optional[str] = None
        details: list[str] = []

        for f in findings:
            sev_weight = self._severity_weights.get(f.severity.value, 0.1)
            confidence_weight = f.confidence
            combined = sev_weight * confidence_weight
            weighted_sum += combined
            weight_total += 1.0

            sev_val = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                f.severity.value, 0
            )
            if sev_val > top_severity_val:
                top_severity_val = sev_val
                top_severity_name = f.severity.value

            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                details.append(f"[{f.severity.value}] {f.title}")

        score = (weighted_sum / weight_total * 100.0) if weight_total > 0 else 0.0

        return RiskBreakdown(
            category=category,
            score=min(100.0, score),
            finding_count=len(findings),
            top_severity=top_severity_name,
            details=details[:5],  # top 5 high-severity details
        )

    def _module_weight(self, module: str) -> float:
        """Get weight for a module, defaulting to 0.5."""
        return self._module_weights.get(module, 0.5)

    @staticmethod
    def _score_to_level(score: float) -> str:
        """Convert numeric score to risk level string."""
        if score >= 80.0:
            return "critical"
        if score >= 60.0:
            return "high"
        if score >= 40.0:
            return "medium"
        if score >= 20.0:
            return "low"
        return "minimal"

    @staticmethod
    def _build_summary(
        overall: float,
        level: str,
        findings: list[Finding],
        breakdowns: list[RiskBreakdown],
    ) -> str:
        """Build a human-readable summary of the risk assessment."""
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        total = len(findings)

        lines = [f"Overall risk: {level.upper()} ({overall:.1f}/100)"]
        lines.append(f"Total findings: {total} (critical={critical}, high={high})")

        if breakdowns:
            lines.append("Category breakdown:")
            for b in sorted(breakdowns, key=lambda x: -x.score):
                lines.append(
                    f"  - {b.category}: {b.score:.1f}/100 ({b.finding_count} findings)"
                )

        return "\n".join(lines)
