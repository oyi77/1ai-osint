"""Pydantic models for structured AI responses."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"
    NAME = "name"
    ORGANIZATION = "organization"
    ADDRESS = "address"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    CRYPTO_ADDRESS = "crypto_address"
    OTHER = "other"


class RelationshipType(str, Enum):
    SAME_PERSON = "same_person"
    ASSOCIATED = "associated"
    COLLEAGUE = "colleague"
    FAMILY = "family"
    EMPLOYER = "employer"
    SERVICE_PROVIDER = "service_provider"


class ExtractedEntity(BaseModel):
    """A single entity extracted from text."""

    entity_type: EntityType
    value: str = Field(..., description="Raw entity value")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = Field(default="", description="Surrounding text context")


class EntityExtractionResult(BaseModel):
    """AI response for entity extraction."""

    entities: list[ExtractedEntity] = Field(default_factory=list)
    relationships: list[dict] = Field(
        default_factory=list,
        description="Extracted relationships between entities",
    )
    summary: str = ""
    raw_response: str = ""


class FindingAssessment(BaseModel):
    """AI assessment of a single finding."""

    finding_id: str
    is_false_positive: bool = False
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reasoning: str = ""
    adjusted_severity: Optional[str] = None


class FalsePositiveResult(BaseModel):
    """AI response for false positive filtering."""

    assessments: list[FindingAssessment] = Field(default_factory=list)
    summary: str = ""
    raw_response: str = ""


class CorrelationResult(BaseModel):
    """AI response for correlating identities across sources."""

    correlated_groups: list[list[str]] = Field(
        default_factory=list,
        description="Groups of ZKIT hashes that likely refer to the same entity",
    )
    relationships: list[dict] = Field(
        default_factory=list,
        description="Explicit relationships discovered",
    )
    summary: str = ""


class LanguageStyle(BaseModel):
    """Language style characteristics for behavioral profiling."""

    formality_level: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="0=very informal, 1=very formal",
    )
    common_phrases: list[str] = Field(default_factory=list)
    writing_complexity: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="0=simple, 1=very complex",
    )
    sentiment_tendency: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="0=very negative, 0.5=neutral, 1=very positive",
    )


class ActivityTimes(BaseModel):
    """Temporal activity patterns."""

    active_hours: list[int] = Field(
        default_factory=list,
        description="Hours of day (0-23) when entity is most active",
    )
    active_days: list[str] = Field(
        default_factory=list,
        description="Days of week when entity is most active",
    )
    typical_frequency: Optional[str] = Field(
        default=None,
        description="daily, weekly, sporadic",
    )


class BehavioralProfile(BaseModel):
    """Behavioral profile for a monitored entity."""

    language_style: LanguageStyle = Field(default_factory=LanguageStyle)
    activity_times: ActivityTimes = Field(default_factory=ActivityTimes)
    platform_preferences: dict[str, float] = Field(
        default_factory=dict,
        description="Platform name -> activity score (0.0-1.0)",
    )
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    sample_count: int = Field(default=0, ge=0)
    summary: str = ""


class BehavioralAnalysisResult(BaseModel):
    """Result of behavioral profiling analysis."""

    profiles: dict[str, BehavioralProfile] = Field(
        default_factory=dict,
        description="Entity identifier -> BehavioralProfile",
    )
    summary: str = ""
    raw_response: str = ""


class DetectedAnomaly(BaseModel):
    """A single detected anomaly."""

    anomaly_type: str = Field(
        ...,
        description="Type of anomaly: deviation, new_platform, style_change, etc.",
    )
    description: str = ""
    severity: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    entity: str = Field(default="", description="Entity exhibiting the anomaly")
    dimension: str = Field(
        default="",
        description="Which dimension is anomalous (timing, language, platform)",
    )
    baseline_value: Optional[str] = None
    observed_value: Optional[str] = None
    z_score: Optional[float] = None


class AnomalyReport(BaseModel):
    """Report of detected anomalies for an entity."""

    detected_anomalies: list[DetectedAnomaly] = Field(default_factory=list)
    overall_severity: float = Field(default=0.0, ge=0.0, le=1.0)
    overall_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    summary: str = ""


class AnomalyDetectionResult(BaseModel):
    """Result of anomaly detection analysis."""

    reports: dict[str, AnomalyReport] = Field(
        default_factory=dict,
        description="Entity identifier -> AnomalyReport",
    )
    summary: str = ""
    raw_response: str = ""
