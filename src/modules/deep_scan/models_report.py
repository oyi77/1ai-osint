"""Pydantic models for the intel-grade deep scan report.

Adds EvidenceItem, ConfidenceBreakdown, RiskAssessment, IdentityGraph,
TimelineEntry, IdentityNode/Edge, PivotSuggestion, IntelReport on top of the
existing DeepScanResult. Also contains the source reliability registry.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# --- Reliability ---
SourceReliability = str  # NATO A-F string, e.g. "A", "B", "C", "D", "E", "F"


def rate_source(source: str) -> str:
    """Rate a source by its platform/identifier.
    Returns NATO Admiralty System rating (A-F).
    """
    s = (source or "").lower().strip()

    # Strip "source_" prefix used by source adapters
    if s.startswith("source_"):
        s = s[7:]

    for suffix in ("_osint", "_finder", "_scanner", "_checker", "_recon"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    if s in {"github", "gitlab", "linkedin"}:
        return "B"
    if s in {"twitter", "instagram", "facebook", "reddit", "telegram", "youtube", "tiktok", "pinterest", "social"}:
        return "C"
    if s in {"google", "bing", "duckduckgo", "yandex", "leak_lookup", "leak_aggregator", "dehashed", "leakcheck"}:
        return "D"
    if s in {"truecaller", "whocallsme", "everycaller"}:
        return "C"
    if s in {"etherscan", "bscscan", "solscan", "blockchain_info", "mempool"}:
        return "B"
    if s in {"snylla", "snusbase", "dehashed", "leakcheck", "intelx", "hibp"}:
        return "C"
    return "F"


# --- Evidence ---
class EvidenceItem(BaseModel):
    """A single piece of evidence backing a finding or identifier."""
    id: str = ""
    identifier_value: str = ""
    identifier_type: str = ""
    source: str = ""
    source_reliability: str = "F"
    url: Optional[str] = None
    http_status: Optional[int] = None
    snippet: Optional[str] = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0
    notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    display_value: str = ""
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# --- Confidence ---
class ConfidenceBreakdown(BaseModel):
    """Deterministic confidence score components."""
    existence: float = 0.0
    uniqueness: float = 0.0
    cross_module: float = 0.0
    temporal: float = 0.0

    @property
    def total(self) -> float:
        """Weighted formula: 0.40·existence + 0.20·uniqueness + 0.25·cross_module + 0.15·temporal."""
        raw = 0.40 * self.existence + 0.20 * self.uniqueness + 0.25 * self.cross_module + 0.15 * self.temporal
        return round(raw, 3)

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

    def compute(self) -> None:
        """Post-process: clamp all components to [0, 1]."""
        self.existence = max(0.0, min(1.0, self.existence))
        self.uniqueness = max(0.0, min(1.0, self.uniqueness))
        self.cross_module = max(0.0, min(1.0, self.cross_module))
        self.temporal = max(0.0, min(1.0, self.temporal))


# --- Risk ---
class RiskLevel(str, Enum):
    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFactor(BaseModel):
    """A single risk assessment factor."""
    rule: str = ""
    description: str = ""
    weight: float = 0.0
    triggered: bool = False


class RiskAssessment(BaseModel):
    """Rule-based risk assessment."""
    level: RiskLevel = RiskLevel.NONE
    score: float = 0.0
    factors: list[RiskFactor] = Field(default_factory=list)
    reasoning: str = ""


# --- Timeline ---
class TimelineEntry(BaseModel):
    """When a piece of evidence was captured."""
    timestamp: Optional[datetime] = None
    source: str = ""
    event: str = ""
    detail: str = ""
    confidence: float = 0.0


# --- Identity Graph ---
class IdentityNode(BaseModel):
    """A node in the identity graph."""
    id: str = ""
    label: str = ""
    type: str = ""
    weight: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class IdentityEdge(BaseModel):
    """An edge linking two identity nodes."""
    source_id: str = ""
    target_id: str = ""
    relationship: str = ""
    weight: float = 1.0
    evidence_ids: list[str] = Field(default_factory=list)


class IdentityGraph(BaseModel):
    """Identity graph with nodes and edges."""
    nodes: list[IdentityNode] = Field(default_factory=list)
    edges: list[IdentityEdge] = Field(default_factory=list)


# --- Pivots ---
class PivotSuggestion(BaseModel):
    """Recommended next step for an investigator."""
    target_type: str = ""
    target_value: str = ""
    rationale: str = ""
    priority: int = 0
    expected_sources: list[str] = Field(default_factory=list)


# --- Top-level report ---
class IntelReport(BaseModel):
    """Top-level intel-grade report."""
    report_id: str = ""
    target: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_sec: float = 0.0
    iterations: int = 0
    modules_run: list[str] = Field(default_factory=list)

    evidence: list[EvidenceItem] = Field(default_factory=list)
    confidence_by_identifier: dict[str, ConfidenceBreakdown] = Field(default_factory=dict)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    identity_graph: IdentityGraph = Field(default_factory=IdentityGraph)
    pivots: list[PivotSuggestion] = Field(default_factory=list)
    summary: str = ""
    warnings: list[str] = Field(default_factory=list)
    correlation_clusters: list[dict] = Field(default_factory=list)
    correlation_stats: dict = Field(default_factory=dict)
