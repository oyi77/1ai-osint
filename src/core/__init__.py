"""Core infrastructure — config, caching, rate limiting, data models."""

from src.core.cache import Cache
from src.core.cloak_client import CloakScraper
from src.core.compliance import (
    AuditEntry,
    LegalBasis,
    SourceCompliance,
    get_compliance,
    is_consent_required,
    purge_expired_audit_entries,
    read_audit_entries,
    record_audit,
    registered_sources,
)
from src.core.config import Settings
from src.core.database import Database
from src.core.logging_config import JSONFormatter, setup_logging
from src.core.models import BreachRecord, Finding, Identity, ScanResult, Severity
from src.core.rate_limiter import RateLimiter

__all__ = [
    "AuditEntry",
    "BreachRecord",
    "Cache",
    "CloakScraper",
    "Database",
    "Finding",
    "Identity",
    "JSONFormatter",
    "LegalBasis",
    "RateLimiter",
    "ScanResult",
    "Settings",
    "Severity",
    "SourceCompliance",
    "get_compliance",
    "is_consent_required",
    "purge_expired_audit_entries",
    "read_audit_entries",
    "record_audit",
    "registered_sources",
    "setup_logging",
]
