"""Pydantic models for the identity graph data structure.

All node identifiers are salted SHA-256 hashes — no raw PII is ever stored.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Supported node types in the identity graph."""

    EMAIL_HASH = "email_hash"
    USERNAME_HASH = "username_hash"
    PHONE_HASH = "phone_hash"
    DOMAIN_HASH = "domain_hash"


class GraphNode(BaseModel):
    """A hashed attribute node in the identity graph."""

    node_id: str = Field(..., description="ZKIT salted SHA-256 hash (node key)")
    node_type: NodeType = Field(..., description="Type of hashed attribute")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, source: Optional[str] = None) -> None:
        """Update last_seen timestamp and optionally add a source."""
        self.last_seen = datetime.now(timezone.utc)
        if source and source not in self.sources:
            self.sources.append(source)


class GraphEdge(BaseModel):
    """A co-occurrence edge connecting two attribute nodes."""

    source_id: str = Field(..., description="Source node_id (hash)")
    target_id: str = Field(..., description="Target node_id (hash)")
    weight: float = Field(default=1.0, ge=0.0, description="Edge confidence weight")
    co_occurrences: int = Field(default=1, ge=1, description="Number of co-observations")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, source: Optional[str] = None, weight_increment: float = 0.0) -> None:
        """Update co-occurrence count, weight, and timestamp."""
        self.last_seen = datetime.now(timezone.utc)
        self.co_occurrences += 1
        self.weight = min(self.weight + weight_increment, 1.0)
        if source and source not in self.sources:
            self.sources.append(source)
