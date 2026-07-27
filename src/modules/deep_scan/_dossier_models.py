"""Pydantic models for target-dossier intelligence reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class EmailIntel(BaseModel):
    address: str = ""
    source: str = ""  # where it was found
    confidence: float = 0.0
    breaches: list[str] = Field(default_factory=list)
    gravatar_linked: bool = False


class PhoneDossierIntel(BaseModel):
    number: str = ""
    operator: str = ""
    source: str = ""
    whatsapp_registered: Optional[bool] = None
    confidence: float = 0.0


class SocialAccount(BaseModel):
    platform: str = ""
    username: str = ""
    url: str = ""
    bio: str = ""
    followers: int = 0
    profile_picture: str = ""
    verified: bool = False
    source: str = ""


class WorkHistory(BaseModel):
    company: str = ""
    title: str = ""
    source: str = ""
    confidence: float = 0.0


class Education(BaseModel):
    institution: str = ""
    degree: str = ""
    source: str = ""


class TargetDossier(BaseModel):
    """Complete intelligence dossier for a target individual."""

    # Meta
    report_id: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    classification: str = "UNCLASSIFIED // OSINT // LAWFUL USE ONLY"

    # Identity
    full_name: str = ""
    aliases: list[str] = Field(default_factory=list)
    profile_pictures: list[str] = Field(default_factory=list)

    # Contact
    emails: list[EmailIntel] = Field(default_factory=list)
    phones: list[PhoneDossierIntel] = Field(default_factory=list)

    # Employment
    current_employer: str = ""
    job_title: str = ""
    work_history: list[WorkHistory] = Field(default_factory=list)

    # Location
    known_locations: list[str] = Field(default_factory=list)
    city: str = ""
    country: str = ""

    # Education
    education: list[Education] = Field(default_factory=list)
    academic_publications: list[str] = Field(default_factory=list)

    # Digital Footprint
    social_accounts: list[SocialAccount] = Field(default_factory=list)
    websites: list[str] = Field(default_factory=list)

    # Security
    breached_services: list[str] = Field(default_factory=list)
    exposed_data_types: list[str] = Field(default_factory=list)
    password_patterns: list[str] = Field(default_factory=list)

    # Crypto
    crypto_addresses: list[str] = Field(default_factory=list)

    # Device / Technical
    devices: list[str] = Field(default_factory=list)

    # Known Associates
    known_associates: list[str] = Field(default_factory=list)

    # Meta
    data_sources_used: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    intelligence_gaps: list[str] = Field(default_factory=list)
    requires_api_keys: list[str] = Field(default_factory=list)
