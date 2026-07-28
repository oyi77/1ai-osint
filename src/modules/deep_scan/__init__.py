"""Deep Scan Engine — Recursive identity investigation.

Takes an initial identifier (name, email, username, phone, NIK, crypto address)
and recursively discovers ALL connected identifiers across all modules until
no new identifiers are found. Generates comprehensive HTML/PDF reports.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.core.models import Finding, ScanResult

logger = logging.getLogger(__name__)


class IdentifierType(str, Enum):
    """Types of identifiers we can discover and track."""

    NAME = "name"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    CRYPTO_ADDRESS = "crypto_address"
    NIK = "nik"  # Indonesian National ID
    SOCIAL_PROFILE = "social_profile"
    URL = "url"
    PASSWORD = "password"
    HASH = "hash"


@dataclass
class Identifier:
    """A discovered identifier with metadata."""

    value: str
    id_type: IdentifierType
    source: str  # Which module found it
    confidence: float = 1.0  # 0.0-1.0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def hash(self) -> str:
        return hashlib.sha256(f"{self.id_type}:{self.value}".encode()).hexdigest()[:16]


@dataclass
class DeepScanResult:
    """Complete result of a deep scan investigation."""

    target: str
    started_at: datetime
    completed_at: datetime | None = None
    identifiers: list[Identifier] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_results: list[ScanResult] = field(default_factory=list)
    iterations: int = 0
    max_iterations: int = 10
    errors: list[str] = field(default_factory=list)
    zkit_result: Any | None = None  # CorrelationResult from identity_tracking
    dossier: Any | None = None  # TargetDossier from Phase 7

    @property
    def duration_sec(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    @property
    def identifier_count(self) -> int:
        return len(self.identifiers)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def get_identifiers_by_type(self, id_type: IdentifierType) -> list[Identifier]:
        return [i for i in self.identifiers if i.id_type == id_type]

    def get_emails(self) -> list[str]:
        return [i.value for i in self.identifiers if i.id_type == IdentifierType.EMAIL]

    def get_usernames(self) -> list[str]:
        return [i.value for i in self.identifiers if i.id_type == IdentifierType.USERNAME]

    def get_phones(self) -> list[str]:
        return [i.value for i in self.identifiers if i.id_type == IdentifierType.PHONE]

    def get_domains(self) -> list[str]:
        return [i.value for i in self.identifiers if i.id_type == IdentifierType.DOMAIN]

    def get_crypto_addresses(self) -> list[str]:
        return [i.value for i in self.identifiers if i.id_type == IdentifierType.CRYPTO_ADDRESS]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "finding_count": self.finding_count,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_sec": self.duration_sec,
            "iterations": self.iterations,
            "identifiers": [
                {
                    "value": i.value,
                    "type": i.id_type.value,
                    "source": i.source,
                    "confidence": i.confidence,
                    "first_seen": i.first_seen.isoformat(),
                }
                for i in self.identifiers
            ],
            "findings": [
                {
                    "id": f.id,
                    "module": f.module,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "raw_data": f.raw_data,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }
