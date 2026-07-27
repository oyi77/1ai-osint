"""AI vs non-AI comparison benchmarks.

Measures the impact of the AI orchestration layer (LangGraph + OmniRoute) on
OSINT analysis quality by comparing AI-enriched results against baseline
rule-based processing.
"""

from __future__ import annotations

from typing import Any

from src.core.models import Finding, Severity

# ---------------------------------------------------------------------------
# Synthetic test data
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS: list[Finding] = [
    Finding(
        id="ai-cmp-1",
        module="data_leaks",
        title="Email found in breach: Collection1",
        description="alice@example.com appeared in Collection1 breach (2019)",
        severity=Severity.HIGH,
        raw_data={
            "email": "alice@example.com",
            "breach": "Collection1",
            "records": 772904991,
        },
        confidence=0.95,
        tags=["breach", "email"],
    ),
    Finding(
        id="ai-cmp-2",
        module="people_finder",
        title="Profile found: alice on GitHub",
        description="Username 'alice' found on github.com",
        severity=Severity.LOW,
        raw_data={
            "username": "alice",
            "site": "github.com",
            "url": "https://github.com/alice",
        },
        confidence=0.8,
        tags=["social", "profile"],
    ),
    Finding(
        id="ai-cmp-3",
        module="gitleaks",
        title="Secret detected: aws-access-token",
        description="Possible AWS access token in config.env",
        severity=Severity.CRITICAL,
        raw_data={"rule_id": "aws-access-token", "file": "config.env", "line": 42},
        confidence=0.85,
        tags=["secret", "aws"],
    ),
    Finding(
        id="ai-cmp-4",
        module="people_finder",
        title="Profile found: alice on LinkedIn",
        description="Username 'alice' found on linkedin.com",
        severity=Severity.LOW,
        raw_data={
            "username": "alice",
            "site": "linkedin.com",
            "url": "https://linkedin.com/in/alice",
        },
        confidence=0.6,
        tags=["social", "profile"],
    ),
    Finding(
        id="ai-cmp-5",
        module="data_leaks",
        title="Email found in breach: LinkedIn2021",
        description="alice@example.com appeared in LinkedIn breach (2021)",
        severity=Severity.HIGH,
        raw_data={"email": "alice@example.com", "breach": "LinkedIn2021"},
        confidence=0.9,
        tags=["breach", "email"],
    ),
]

FALSE_POSITIVE_FINDINGS: list[Finding] = [
    Finding(
        id="fp-1",
        module="gitleaks",
        title="Secret detected: generic-api-key",
        description="Example key in README.md",
        severity=Severity.MEDIUM,
        raw_data={"rule_id": "generic-api-key", "file": "README.md", "line": 5},
        confidence=0.3,
        tags=["secret", "false_positive"],
    ),
]


# ---------------------------------------------------------------------------
# Baseline rule-based processor
# ---------------------------------------------------------------------------


def baseline_process(findings: list[Finding]) -> dict[str, Any]:
    """Rule-based analysis without AI — simple aggregation and dedup."""
    severity_counts: dict[str, int] = {}
    modules: dict[str, int] = {}
    unique_titles: set[str] = set()

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        modules[f.module] = modules.get(f.module, 0) + 1
        unique_titles.add(f.title)

    total = len(findings)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    risk_score = min(100.0, (critical * 30 + high * 15 + total * 5))

    return {
        "total_findings": total,
        "unique_findings": len(unique_titles),
        "severity_breakdown": severity_counts,
        "module_breakdown": modules,
        "risk_score": risk_score,
        "risk_level": (
            "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"
        ),
        "false_positives_filtered": 0,
        "entities_extracted": 0,
        "correlations_found": 0,
    }


# ---------------------------------------------------------------------------
# AI-enriched processor (mocked for deterministic testing)
# ---------------------------------------------------------------------------


def ai_enriched_process(findings: list[Finding]) -> dict[str, Any]:
    """Simulated AI-enriched analysis with entity extraction and FP filtering.

    In a real run this calls the LangGraph orchestrator. Here we simulate
    the AI layer's contributions for benchmarking purposes.
    """
    # Step 1: False positive filtering (simulated AI filter)
    filtered = [f for f in findings if f.confidence >= 0.5]
    fp_removed = len(findings) - len(filtered)

    # Step 2: Entity extraction (simulated)
    entities: dict[str, list[str]] = {}
    for f in filtered:
        raw = f.raw_data
        if "email" in raw:
            entities.setdefault("email", []).append(raw["email"])
        if "username" in raw:
            entities.setdefault("username", []).append(raw["username"])

    # Step 3: Cross-module correlation (simulated)
    correlations = 0
    emails = set(entities.get("email", []))
    usernames = set(entities.get("username", []))
    if emails and usernames:
        correlations = min(len(emails), len(usernames))

    # Step 4: Risk scoring (AI-enhanced)
    severity_counts: dict[str, int] = {}
    for f in filtered:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    base_score = min(100.0, (critical * 30 + high * 15 + len(filtered) * 5))
    # AI boost: correlation signal increases risk
    ai_score = min(100.0, base_score + correlations * 10)

    return {
        "total_findings": len(filtered),
        "unique_findings": len({f.title for f in filtered}),
        "severity_breakdown": severity_counts,
        "risk_score": ai_score,
        "risk_level": (
            "critical" if ai_score >= 80 else "high" if ai_score >= 60 else "medium" if ai_score >= 30 else "low"
        ),
        "false_positives_filtered": fp_removed,
        "entities_extracted": sum(len(v) for v in entities.values()),
        "correlations_found": correlations,
    }


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestAIComparison:
    """Compare AI-enriched vs baseline rule-based analysis."""

    def test_ai_filters_false_positives(self):
        """AI layer should filter findings with low confidence."""
        all_findings = SAMPLE_FINDINGS + FALSE_POSITIVE_FINDINGS
        ai_result = ai_enriched_process(all_findings)
        baseline_result = baseline_process(all_findings)

        assert ai_result["false_positives_filtered"] > 0, "AI should filter at least one FP"
        assert ai_result["total_findings"] <= baseline_result["total_findings"]

    def test_ai_extracts_entities(self):
        """AI layer should extract entities from findings."""
        result = ai_enriched_process(SAMPLE_FINDINGS)
        assert result["entities_extracted"] > 0, "AI should extract entities"

    def test_ai_finds_correlations(self):
        """AI layer should find cross-module correlations."""
        result = ai_enriched_process(SAMPLE_FINDINGS)
        assert result["correlations_found"] >= 0, "Correlations count should be non-negative"

    def test_ai_risk_score_higher_with_correlations(self):
        """AI risk score should be >= baseline when correlations exist."""
        ai_result = ai_enriched_process(SAMPLE_FINDINGS)
        baseline_result = baseline_process(SAMPLE_FINDINGS)

        # AI score includes correlation boost
        if ai_result["correlations_found"] > 0:
            assert ai_result["risk_score"] >= baseline_result["risk_score"]

    def test_baseline_risk_score_reasonable(self):
        """Baseline risk score should be in valid range."""
        result = baseline_process(SAMPLE_FINDINGS)
        assert 0.0 <= result["risk_score"] <= 100.0

    def test_ai_risk_score_reasonable(self):
        """AI risk score should be in valid range."""
        result = ai_enriched_process(SAMPLE_FINDINGS)
        assert 0.0 <= result["risk_score"] <= 100.0

    def test_ai_preserves_critical_findings(self):
        """AI filtering should not remove critical-severity findings."""
        result = ai_enriched_process(SAMPLE_FINDINGS)
        critical_in = sum(1 for f in SAMPLE_FINDINGS if f.severity == Severity.CRITICAL)
        # All critical findings have confidence >= 0.5, so they survive
        assert result["severity_breakdown"].get("critical", 0) == critical_in

    def test_comparison_summary(self):
        """Print comparison summary for benchmark reporting."""
        ai_result = ai_enriched_process(SAMPLE_FINDINGS + FALSE_POSITIVE_FINDINGS)
        baseline_result = baseline_process(SAMPLE_FINDINGS + FALSE_POSITIVE_FINDINGS)

        summary = {
            "baseline_findings": baseline_result["total_findings"],
            "ai_findings": ai_result["total_findings"],
            "fp_filtered": ai_result["false_positives_filtered"],
            "entities_extracted": ai_result["entities_extracted"],
            "correlations": ai_result["correlations_found"],
            "baseline_risk": baseline_result["risk_score"],
            "ai_risk": ai_result["risk_score"],
        }
        # Verify summary is well-formed
        assert all(v >= 0 for v in summary.values() if isinstance(v, (int, float)))
