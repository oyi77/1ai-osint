"""Data models for the monitoring engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ChangeType(str, Enum):
    """Categories of change that can be detected."""

    NEW_EMAIL = "new_email"
    NEW_HANDLE = "new_handle"
    NEW_DOMAIN = "new_domain"
    NEW_PHONE = "new_phone"
    NEW_CRYPTO_ADDRESS = "new_crypto_address"
    NEW_BREACH = "new_breach"
    NEW_SOCIAL_ACCOUNT = "new_social_account"
    RISK_SCORE_CHANGE = "risk_score_change"
    FIELD_CHANGE = "field_change"
    ATTRIBUTE_CHANGE = "attribute_change"
    SOURCE_DISAPPEARED = "source_disappeared"
    CONFIDENCE_CHANGE = "confidence_change"


class ChangeSeverity(str, Enum):
    """Severity of a detected change."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WatchlistTarget(BaseModel):
    """A watched entity in the monitor."""

    target: str = Field(..., description="The identifier being watched")
    target_type: str = Field(..., description="One of: email, username, domain, phone, wallet")
    tags: list[str] = Field(default_factory=list)
    interval_hours: int = Field(default=24, ge=1, description="Hours between re-scans")
    last_scan: datetime | None = Field(default=None, description="When the target was last scanned")
    alert_channels: list[str] = Field(
        default_factory=lambda: ["console"],
        description="Channels: console, file, telegram, webhook",
    )
    severity_threshold: str = Field(
        default="medium",
        description="Minimum severity to trigger an alert (info|low|medium|high|critical)",
    )
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChangeEvent(BaseModel):
    """A single detected change between two intelligence snapshots."""

    event_id: str = Field(..., description="Unique identifier for this event")
    target: str = Field(..., description="The entity the change relates to")
    change_type: ChangeType = Field(..., description="Category of the change")
    old_value: str | None = Field(default=None, description="Previous value (if applicable)")
    new_value: str | None = Field(default=None, description="Current value (if applicable)")
    source_module: str = Field(..., description="The module that produced the change data")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: ChangeSeverity = Field(default=ChangeSeverity.INFO, description="Computed severity")
    description: str = Field(default="", description="Human-readable change summary")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in this change")
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}


class AlertRule(BaseModel):
    """A rule defining when and how to alert on changes."""

    rule_id: str = Field(..., description="Unique rule identifier")
    target_pattern: str = Field(..., description="Glob or regex pattern to match target names")
    condition: str = Field(
        ...,
        description="Condition expression, e.g. 'severity >= high or change_type == new_breach'",
    )
    channel: str = Field(default="console", description="Alert channel to use")
    enabled: bool = Field(default=True, description="Whether this rule is active")
    cooldown_minutes: int = Field(
        default=60,
        ge=0,
        description="Minimum minutes between repeat alerts for the same event type",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
