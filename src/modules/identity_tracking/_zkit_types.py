"""ZKIT Protocol data types — constants, normalization, and pipeline types.

Extracted from zkit_engine.py to reduce file size.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.modules.identity_tracking.identity_graph import NodeType

# ---------------------------------------------------------------------------
# Supported attribute types and normalization
# ---------------------------------------------------------------------------

ATTRIBUTE_TYPE_MAP: dict[str, NodeType] = {
    "email": NodeType.EMAIL_HASH,
    "username": NodeType.USERNAME_HASH,
    "phone": NodeType.PHONE_HASH,
    "domain": NodeType.DOMAIN_HASH,
}

# Known PII field names that must never appear in output
PII_FIELDS = frozenset(
    {
        "email",
        "username",
        "phone",
        "domain",
        "ip",
        "ip_address",
        "password",
        "password_plain",
        "password_hash",
        "address",
        "ssn",
        "credit_card",
        "name",
        "full_name",
        "first_name",
        "last_name",
    }
)


def normalize_attribute(attr_type: str, value: str) -> str:
    """Normalize an attribute value before hashing.

    Per spec section 7.1:
    - email: lowercase
    - username: as-is (platform normalization may apply later)
    - phone: strip spaces/dashes (E.164 recommended)
    - domain: lowercase, no protocol prefix
    """
    if attr_type == "email":
        return value.strip().lower()
    if attr_type == "domain":
        v = value.strip().lower()
        for prefix in ("https://", "http://", "www."):
            if v.startswith(prefix):
                v = v[len(prefix) :]
        return v.rstrip("/")
    if attr_type == "phone":
        return value.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    return value.strip()


# ---------------------------------------------------------------------------
# Pipeline data types
# ---------------------------------------------------------------------------


class CorrelationConfidence(str, Enum):
    """Confidence tiers for identity correlations."""

    HIGH = "high"  # score >= 0.75
    MEDIUM = "medium"  # score >= 0.4
    LOW = "low"  # score < 0.4


@dataclass
class IngestedRecord:
    """A normalized record ready for hashing."""

    attributes: dict[str, str]  # attr_type -> raw_value (transient, never persisted)
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelatedCluster:
    """A cluster of identity hashes believed to belong to the same entity."""

    cluster_id: str
    hash_members: list[str]  # zkit hashes in this cluster
    attribute_types: set[str]  # e.g. {"email_hash", "username_hash"}
    score: float  # [0.0, 1.0]
    confidence: CorrelationConfidence
    edge_count: int
    total_co_occurrences: int
    sources: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ZKITOutput:
    """Final sanitized output — no raw PII."""

    investigation_id: str
    salt_fingerprint: str  # first 16 chars of salt SHA-256 (not the salt itself)
    clusters: list[CorrelatedCluster]
    graph_stats: dict[str, Any]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
