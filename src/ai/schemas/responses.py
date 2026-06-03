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
    OTHER = "other"


class ExtractedEntity(BaseModel):
    """A single entity extracted from text."""

    entity_type: EntityType
    value: str = Field(..., description="Raw entity value")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = Field(default="", description="Surrounding text context")


class EntityExtractionResult(BaseModel):
    """AI response for entity extraction."""

    entities: list[ExtractedEntity] = Field(default_factory=list)
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
