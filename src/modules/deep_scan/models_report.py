"""Pydantic models for the intel-grade deep scan report.

Adds EvidenceItem, SourceAttribution, ConfidenceBreakdown, RiskAssessment,
TimelineEntry, IdentityNode/Edge, PivotSuggestion, IntelReport on top of the
existing DeepScanResult. Also contains the source reliability registry.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Reliability(str, Enum):
    """NATO Admiralty-style source reliability rating.

    A = completely reliable, B = usually reliable, C = fairly reliable,
    D = not usually reliable, E = unreliable, F = cannot be judged.
    """
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


# Source reliability registry. Anything not listed defaults to F ("cannot be judged").
DEFAULT_RELIABILITY: dict[str, Reliability] = {
    # Tier A: official, verifiable first-party
    "github": Reliability.A,
    "gitlab": Reliability.A,
    "linkedin": Reliability.B,  # rate-limited/blocked, but data is first-party
    "domain_whois": Reliability.A,
    "ssl_cert": Reliability.A,
    "dns_records": Reliability.A,
    # Tier B: aggregator / API with account verification
    "twitter": Reliability.B,
    "instagram": Reliability.B,
    "reddit": Reliability.B,
    "telegram": Reliability.B,
    "pypi": Reliability.A,
    "npm": Reliability.A,
    # Tier C: third-party scrapers
    "google": Reliability.C,
    "bing": Reliability.C,
    "duckduckgo": Reliability.C,
    "haveibeenpwned": Reliability.A,
    "dehashed": Reliability.B,
    # Tier F: everything we cannot directly verify
    "leak_aggregator": Reliability.F,
    "input": Reliability.A,
}


def reliability_for(source: str) -> Reliability:
    """Return the reliability rating for a given source name."""
    return DEFAULT_RELIABILITY.get(source, Reliability.F)


class EvidenceItem(BaseModel):
    """A single piece of evidence backing a finding or identifier."""
    evidence_id: str
    value: str
    source: str
    source_reliability: Reliability = Reliability.F
    url: Optional[str] = None
    http_status: Optional[int] = None
    snippet: Optional[str] = None
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    exists: bool = True


class ConfidenceBreakdown(BaseModel):
    """Deterministic confidence score, summing to 1.0.

    existence: 0.40 — does the target exist at the source? (HTTP 200, not 404)
    uniqueness: 0.20 — is the identifier unique to one person?
    cross_module: 0.25 — do multiple modules agree?
    temporal: 0.15 — is the data recent and verifiable?
    """
    existence: float = 0.0
    uniqueness: float = 0.0
    cross_module: float = 0.0
    temporal: float = 0.0

    @property
    def total(self) -> float:
        return round(self.existence + self.uniqueness + self.cross_module + self.temporal, 3)

    @property
    def grade(self) -> str:
        t = self.total
        if t >= 0.85:
            return "high"
        if t >= 0.6:
            return "medium"
        if t >= 0.3:
            return "low"
        return "unverified"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(BaseModel):
    """Rule-based risk assessment derived from collected identifiers."""
    level: RiskLevel = RiskLevel.INFO
    score: int = 0  # 0..100
    reasons: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    """When a piece of evidence was captured."""
    timestamp: datetime
    source: str
    event: str
    value: str
    url: Optional[str] = None


class IdentityNode(BaseModel):
    """A node in the identity graph: a discovered identifier or attribute."""
    node_id: str
    label: str
    node_type: str  # email, phone, social, crypto, domain, name
    value: str
    source: str
    reliability: Reliability = Reliability.F
    confidence: float = 0.0


class IdentityEdge(BaseModel):
    """An edge linking two identity nodes with a relationship reason."""
    source_node: str
    target_node: str
    relationship: str  # co-occurrence, profile_match, email_linked, etc.
    evidence: Optional[str] = None
    weight: float = 1.0


class PivotSuggestion(BaseModel):
    """Recommended next step for an investigator."""
    pivot_id: str
    action: str  # search, query, scrape
    target: str
    rationale: str
    expected_yield: str  # emails, profiles, breaches, etc.
    priority: int = 0  # higher = more important


class IntelReport(BaseModel):
    """Top-level intel-grade report aggregating all the above."""
    report_id: str
    target: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_sec: float = 0.0
    iterations: int = 0
    modules_used: list[str] = Field(default_factory=list)

    identifiers: list[Any] = Field(default_factory=list)  # type: ignore[type-arg]
    findings: list[Any] = Field(default_factory=list)  # type: ignore[type-arg]

    evidence: list[EvidenceItem] = Field(default_factory=list)
    confidence: dict[str, ConfidenceBreakdown] = Field(default_factory=dict)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    graph_nodes: list[IdentityNode] = Field(default_factory=list)
    graph_edges: list[IdentityEdge] = Field(default_factory=list)
    pivots: list[PivotSuggestion] = Field(default_factory=list)

    source_reliability_table: dict[str, Reliability] = Field(default_factory=dict)
    next_steps: list[str] = Field(default_factory=list)
    schema_version: str = "1.0.0"

    @property
    def identifier_count(self) -> int:
        return len(self.identifiers)

    @property
    def finding_count(self) -> int:
        return len(self.findings)
