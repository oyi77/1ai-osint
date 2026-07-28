"""ZKIT privacy-preserving report formatter.

Generates reports using only hashed identifiers -- no raw PII ever
appears in output. Integrates with ReportGenerator and provides
PII redaction auditing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.models import BreachRecord, Finding, Identity, ScanResult
from src.modules.identity_tracking.zkit_engine import (
    CorrelatedCluster,
)


@dataclass
class RedactionAuditEntry:
    """A single redaction event in the audit log."""

    field_name: str
    original_length: int
    redacted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_module: str = ""


@dataclass
class RedactionAudit:
    """Audit log of all PII redactions performed."""

    entries: list[RedactionAuditEntry] = field(default_factory=list)
    total_redactions: int = 0
    pii_fields_redacted: set[str] = field(default_factory=set)

    def add(self, field_name: str, original_length: int, source: str = "") -> None:
        """Record a redaction event."""
        self.entries.append(
            RedactionAuditEntry(
                field_name=field_name,
                original_length=original_length,
                source_module=source,
            )
        )
        self.total_redactions += 1
        self.pii_fields_redacted.add(field_name)

    def to_dict(self) -> dict[str, Any]:
        """Serialize audit log to dict."""
        return {
            "total_redactions": self.total_redactions,
            "pii_fields_redacted": sorted(self.pii_fields_redacted),
            "entries": [
                {
                    "field_name": e.field_name,
                    "original_length": e.original_length,
                    "redacted_at": e.redacted_at.isoformat(),
                    "source_module": e.source_module,
                }
                for e in self.entries
            ],
        }


class ZKITFormatter:
    """Formats reports using only ZKIT-hashed identifiers.

    All PII fields are replaced with salted SHA-256 hashes. The formatter
    also produces a redaction audit log documenting every PII field that
    was removed from the output.

    Usage:
        formatter = ZKITFormatter(salt="investigation-salt")
        report = formatter.format(scan_results)
        audit = formatter.get_audit()
    """

    # PII field names that must be hashed in output
    _PII_KEYS = frozenset(
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

    def __init__(self, salt: str = "") -> None:
        """Args:
        salt: ZKIT salt for hashing identifiers.

        """
        self._salt = salt
        self._audit = RedactionAudit()

    def _hash_value(self, value: str) -> str:
        """Hash a value with the configured salt using SHA-256."""
        preimage = f"{self._salt}:{value}".encode()
        return hashlib.sha256(preimage).hexdigest()

    def _hash_dict_values(
        self,
        data: dict[str, Any],
        source: str = "",
    ) -> dict[str, Any]:
        """Hash all PII fields in a dict, recording audit entries."""
        hashed: dict[str, Any] = {}
        for k, v in data.items():
            if k in self._PII_KEYS and isinstance(v, str) and v:
                hashed[k] = self._hash_value(v)
                self._audit.add(k, len(v), source=source)
            else:
                hashed[k] = v
        return hashed

    def get_audit(self) -> RedactionAudit:
        """Get the redaction audit log.

        Returns:
            RedactionAudit with all recorded redaction events.

        """
        return self._audit

    def reset_audit(self) -> None:
        """Clear the redaction audit log."""
        self._audit = RedactionAudit()

    # ------------------------------------------------------------------
    # Format ScanResult objects
    # ------------------------------------------------------------------

    def format(self, results: list[ScanResult]) -> str:
        """Format scan results into a ZKIT-only JSON report.

        All PII fields are hashed. The output is a JSON string
        containing only ZKIT identifiers.

        Args:
            results: List of ScanResult objects to format.

        Returns:
            JSON string with all PII hashed.

        """
        self.reset_audit()

        report = {
            "report_type": "1ai-osint-zkit",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "zkit_mode": True,
            "privacy_mode": "full",
            "scan_count": len(results),
            "total_findings": sum(r.finding_count for r in results),
            "total_critical": sum(r.critical_count for r in results),
            "scans": [self._format_scan_result(r) for r in results],
            "redaction_audit": self._audit.to_dict(),
        }
        return json.dumps(report, indent=2, default=str)

    def format_with_clusters(
        self,
        results: list[ScanResult],
        clusters: list[CorrelatedCluster],
        investigation_id: str = "",
    ) -> str:
        """Format scan results with ZKIT correlation clusters.

        Combines scan output with identity correlation clusters
        from the ZKITEngine pipeline.

        Args:
            results: List of ScanResult objects.
            clusters: CorrelatedCluster list from ZKITEngine.
            investigation_id: Investigation identifier.

        Returns:
            JSON string with scans and correlation data.

        """
        self.reset_audit()

        report = {
            "report_type": "1ai-osint-zkit-correlated",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "zkit_mode": True,
            "privacy_mode": "full",
            "investigation_id": investigation_id,
            "scan_count": len(results),
            "total_findings": sum(r.finding_count for r in results),
            "scans": [self._format_scan_result(r) for r in results],
            "correlation_clusters": [self._format_cluster(c) for c in clusters],
            "redaction_audit": self._audit.to_dict(),
        }
        return json.dumps(report, indent=2, default=str)

    def _format_scan_result(self, result: ScanResult) -> dict[str, Any]:
        """Format a ScanResult with all PII hashed."""
        source = result.module
        return {
            "scan_id": result.scan_id,
            "module": result.module,
            "target_hash": self._hash_value(result.target),
            "status": result.status,
            "findings": [self._format_finding(f, source) for f in result.findings],
            "finding_count": result.finding_count,
            "critical_count": result.critical_count,
            "breach_records": [self._format_breach(br, source) for br in result.breach_records],
            "identities": [self._format_identity(ident) for ident in result.identities],
            "metadata": result.metadata,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "error": result.error,
        }

    def _format_finding(self, finding: Finding, source: str) -> dict[str, Any]:
        """Format a Finding with PII-hashed raw_data."""
        hashed_raw = self._hash_dict_values(finding.raw_data, source=source)
        return {
            "id": finding.id,
            "module": finding.module,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "tags": finding.tags,
            "raw_data": hashed_raw,
            "timestamp": finding.timestamp.isoformat(),
        }

    def _format_breach(self, breach: BreachRecord, source: str) -> dict[str, Any]:
        """Format a BreachRecord with PII hashed."""
        entry: dict[str, Any] = {
            "source": breach.source,
            "severity": breach.severity.value,
            "description": breach.description,
            "data_classes": breach.data_classes,
        }
        if breach.email:
            entry["email_hash"] = self._hash_value(breach.email)
            self._audit.add("email", len(breach.email), source=source)
        if breach.username:
            entry["username_hash"] = self._hash_value(breach.username)
            self._audit.add("username", len(breach.username), source=source)
        if breach.domain:
            entry["domain_hash"] = self._hash_value(breach.domain)
            self._audit.add("domain", len(breach.domain), source=source)
        if breach.phone:
            entry["phone_hash"] = self._hash_value(breach.phone)
            self._audit.add("phone", len(breach.phone), source=source)
        if breach.ip_address:
            entry["ip_hash"] = self._hash_value(breach.ip_address)
            self._audit.add("ip_address", len(breach.ip_address), source=source)
        return entry

    @staticmethod
    def _format_identity(identity: Identity) -> dict[str, Any]:
        """Format an Identity -- already ZKIT-hashed, no raw PII."""
        return {
            "zkit_hash": identity.zkit_hash,
            "correlation_id": identity.correlation_id,
            "sources": identity.sources,
            "confidence": identity.confidence,
        }

    @staticmethod
    def _format_cluster(cluster: CorrelatedCluster) -> dict[str, Any]:
        """Format a CorrelatedCluster for output."""
        return {
            "cluster_id": cluster.cluster_id,
            "hash_members": cluster.hash_members,
            "attribute_types": sorted(cluster.attribute_types),
            "score": cluster.score,
            "confidence": cluster.confidence.value,
            "edge_count": cluster.edge_count,
            "total_co_occurrences": cluster.total_co_occurrences,
            "sources": cluster.sources,
        }

    # ------------------------------------------------------------------
    # Privacy verification
    # ------------------------------------------------------------------

    def verify_no_pii(self, report_json: str) -> list[str]:
        """Verify that a report JSON string contains no raw PII.

        Scans the JSON for known PII field values that should have
        been hashed.

        Args:
            report_json: JSON string to verify.

        Returns:
            List of PII field names found (empty = clean).

        """
        violations: list[str] = []
        try:
            data = json.loads(report_json)
        except json.JSONDecodeError:
            return ["invalid_json"]

        self._scan_for_pii(data, violations)
        return violations

    def _scan_for_pii(self, data: Any, violations: list[str], path: str = "") -> None:
        """Recursively scan data structure for PII fields."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                # Check if a PII field name appears as a key with a non-hash value
                if key in self._PII_KEYS and isinstance(value, str):
                    # A hash is 64 hex chars; anything shorter is suspicious
                    if len(value) != 64 or not all(c in "0123456789abcdef" for c in value):
                        violations.append(current_path)
                # Check for hash-prefixed fields (email_hash etc.) with non-hash values
                if key.endswith("_hash") and isinstance(value, str):
                    if len(value) != 64 or not all(c in "0123456789abcdef" for c in value):
                        violations.append(current_path)
                self._scan_for_pii(value, violations, current_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._scan_for_pii(item, violations, f"{path}[{i}]")
