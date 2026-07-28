"""Shared Pydantic models for 1ai-osint."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single OSINT finding from any module."""

    id: str = Field(..., description="Unique finding identifier")
    module: str = Field(..., description="Source module name")
    title: str = Field(..., description="Short finding description")
    description: str = Field(default="", description="Detailed description")
    severity: Severity = Field(default=Severity.INFO)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)


class BreachRecord(BaseModel):
    """A record from a breach/leak database."""

    source: str = Field(..., description="Breach source name")
    email: str | None = None
    username: str | None = None
    password_hash: str | None = None
    password_plain: str | None = None
    domain: str | None = None
    ip_address: str | None = None
    phone: str | None = None
    breach_date: datetime | None = None
    description: str = ""
    data_classes: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    raw: dict[str, Any] = Field(default_factory=dict)


class Identity(BaseModel):
    """An identity entity tracked by ZKIT."""

    zkit_hash: str = Field(..., description="ZKIT salted SHA-256 hash")
    attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Original attribute names (never persisted with raw values in ZKIT mode)",
    )
    correlation_id: str | None = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class ScanResult(BaseModel):
    """Top-level result container for any scan operation."""

    scan_id: str = Field(..., description="Unique scan identifier")
    module: str = Field(..., description="Module that produced this result")
    target: str = Field(..., description="Scan target (query, URL, path, etc.)")
    status: str = Field(default="ok", description="ok, error, partial")
    findings: list[Finding] = Field(default_factory=list)
    breach_records: list[BreachRecord] = Field(default_factory=list)
    identities: list[Identity] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error: str | None = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
