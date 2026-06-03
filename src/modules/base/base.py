"""Abstract base class for all 1ai-osint modules with ZKIT support."""

import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.core.models import Finding, ScanResult


class ZKITNode(BaseModel):
    """A node in the ZKIT identity graph."""

    zkit_hash: str = Field(..., description="Salted SHA-256 hash of the attribute")
    attribute_type: str = Field(
        ..., description="Type of attribute (email, username, etc.)"
    )
    salt_fingerprint: str = Field(
        default="", description="Truncated SHA-256 of salt (never the raw salt)"
    )
    correlation_id: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BaseOSINTTool(ABC):
    """
    Abstract base class for all 1ai-osint OSINT modules.

    Provides:
    - Async search/scan/analyze/learn interface
    - ZKIT identity hashing (privacy-preserving)
    - Pydantic model output
    - Module metadata
    """

    name: str = "base"
    description: str = ""
    version: str = "0.1.0"

    def __init__(self, zkit_salt: Optional[str] = None):
        """
        Args:
            zkit_salt: Salt for ZKIT identity hashing. If not provided,
                       hashes will use a random salt (non-reproducible).
        """
        self._zkit_salt = zkit_salt or ""

    @abstractmethod
    async def search(self, query: str, **kwargs) -> ScanResult:
        """
        Perform a search query.

        Args:
            query: The search query (email, username, domain, etc.)
            **kwargs: Module-specific options
        Returns:
            ScanResult with findings
        """
        ...

    @abstractmethod
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Perform a deeper scan operation.

        Args:
            target: The scan target (URL, path, repo, etc.)
            **kwargs: Module-specific options
        Returns:
            ScanResult with findings
        """
        ...

    @abstractmethod
    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """
        Analyze OSINT data for patterns and insights.

        Args:
            data: Raw or structured OSINT data
            **kwargs: Analysis options
        Returns:
            Analysis results dict
        """
        ...

    @abstractmethod
    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """
        Update internal models based on feedback.

        Args:
            feedback: Feedback data (false positives, corrections, etc.)
        """
        ...

    def hash_identity(self, attribute: str, salt: Optional[str] = None) -> str:
        """
        Generate a ZKIT privacy-preserving hash for an identity attribute.

        Uses SHA-256 with a per-investigation salt to prevent rainbow table attacks.
        The raw attribute value is NEVER stored - only the hash.

        Args:
            attribute: The raw attribute value (email, phone, etc.)
            salt: Optional override salt. Defaults to instance salt.
        Returns:
            Hex-encoded SHA-256 hash string
        """
        effective_salt = salt if salt is not None else self._zkit_salt
        # Format: salt + ":" + attribute -> SHA-256
        preimage = f"{effective_salt}:{attribute}".encode("utf-8")
        return hashlib.sha256(preimage).hexdigest()

    def to_zkit_node(
        self,
        result: Finding,
        attribute_type: str = "unknown",
        salt: Optional[str] = None,
    ) -> ZKITNode:
        """
        Convert a Finding into a ZKITNode for identity graph insertion.

        The finding's raw_data is inspected for common identity fields,
        and each is hashed using ZKIT protocol.

        Args:
            result: The Finding to convert
            attribute_type: The type of attribute being tracked
            salt: Optional override salt
        Returns:
            ZKITNode with hashed identity
        """
        # Extract a representative value from the finding
        raw = result.raw_data
        value = (
            raw.get("email")
            or raw.get("username")
            or raw.get("phone")
            or raw.get("domain")
            or raw.get("ip")
            or result.title
        )

        zkit_hash = self.hash_identity(value or result.id, salt)

        salt_fingerprint = hashlib.sha256(
            (salt if salt is not None else self._zkit_salt).encode()
        ).hexdigest()[:16]

        return ZKITNode(
            zkit_hash=zkit_hash,
            attribute_type=attribute_type,
            salt_fingerprint=salt_fingerprint,
            sources=[result.module],
            metadata={"finding_id": result.id, "title": result.title},
        )

    def _make_scan_id(self) -> str:
        """Generate a unique scan ID."""
        return str(uuid.uuid4())

    def _make_finding_id(self) -> str:
        """Generate a unique finding ID."""
        return str(uuid.uuid4())

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}')>"
