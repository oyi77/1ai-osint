"""JSON report formatter with ZKIT-compatible hashed identifiers."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from src.core.models import Finding, ScanResult


class JSONFormatter:
    """Formats ScanResult objects into ZKIT-compatible JSON output.

    All PII fields are hashed using SHA-256 with a salt, so raw identifiers
    never appear in the output.
    """

    def __init__(self, salt: str = ""):
        self._salt = salt

    def _hash_value(self, value: str) -> str:
        """Hash a value with the configured salt using SHA-256."""
        preimage = f"{self._salt}:{value}".encode()
        return hashlib.sha256(preimage).hexdigest()

    def _hash_dict_values(self, data: dict[str, Any], keys_to_hash: set[str]) -> dict[str, Any]:
        """Hash specific keys in a dict, leaving others intact."""
        hashed = {}
        for k, v in data.items():
            if k in keys_to_hash and isinstance(v, str):
                hashed[k] = self._hash_value(v)
            else:
                hashed[k] = v
        return hashed

    def _format_finding(self, finding: Finding) -> dict[str, Any]:
        """Format a single Finding with hashed PII fields."""
        pii_keys = {"email", "username", "phone", "domain", "ip", "ip_address"}
        hashed_raw = self._hash_dict_values(finding.raw_data, pii_keys)

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

    def _format_scan_result(self, result: ScanResult) -> dict[str, Any]:
        """Format a ScanResult with all findings ZKIT-hashed."""
        return {
            "scan_id": result.scan_id,
            "module": result.module,
            "target_hash": self._hash_value(result.target),
            "status": result.status,
            "findings": [self._format_finding(f) for f in result.findings],
            "finding_count": result.finding_count,
            "critical_count": result.critical_count,
            "breach_records": [
                {
                    "source": br.source,
                    "email_hash": self._hash_value(br.email) if br.email else None,
                    "username_hash": self._hash_value(br.username) if br.username else None,
                    "domain_hash": self._hash_value(br.domain) if br.domain else None,
                    "severity": br.severity.value,
                    "description": br.description,
                    "data_classes": br.data_classes,
                }
                for br in result.breach_records
            ],
            "identities": [
                {
                    "zkit_hash": id.zkit_hash,
                    "correlation_id": id.correlation_id,
                    "sources": id.sources,
                    "confidence": id.confidence,
                }
                for id in result.identities
            ],
            "metadata": result.metadata,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "error": result.error,
        }

    def format(self, results: list[ScanResult]) -> str:
        """Format multiple ScanResults into a JSON string.

        Args:
            results: List of ScanResult objects to format.

        Returns:
            JSON string with all PII fields hashed.

        """
        report = {
            "report_type": "1ai-osint-json",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "zkit_mode": True,
            "scan_count": len(results),
            "total_findings": sum(r.finding_count for r in results),
            "total_critical": sum(r.critical_count for r in results),
            "scans": [self._format_scan_result(r) for r in results],
        }
        return json.dumps(report, indent=2, default=str)
