"""SARIF 2.1.0 formatter for GitHub Security tab integration."""

import hashlib
from typing import Any

from src.core.models import Finding, ScanResult, Severity

# SARIF severity mapping
_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_SEVERITY_TO_RESULT_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


class SARIFFormatter:
    """Formats ScanResult objects into SARIF 2.1.0 JSON.

    Suitable for upload to GitHub Security tab via the Code Scanning API.
    All PII fields in results are hashed with a configurable salt.
    """

    TOOL_NAME = "1ai-osint"
    TOOL_VERSION = "0.1.0"

    def __init__(self, salt: str = ""):
        self._salt = salt

    def _hash_value(self, value: str) -> str:
        preimage = f"{self._salt}:{value}".encode("utf-8")
        return hashlib.sha256(preimage).hexdigest()

    def _severity_to_level(self, severity: Severity) -> str:
        return _SEVERITY_TO_LEVEL.get(severity, "none")

    def _severity_to_result_level(self, severity: Severity) -> str:
        return _SEVERITY_TO_RESULT_LEVEL.get(severity, "note")

    def _finding_to_rule(self, finding: Finding) -> dict[str, Any]:
        """Create a SARIF reportingDescriptor (rule) from a Finding."""
        return {
            "id": f"{finding.module}/{finding.id}",
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "defaultConfiguration": {
                "level": self._severity_to_level(finding.severity),
            },
            "properties": {
                "tags": finding.tags + [finding.severity.value],
                "precision": "medium",
            },
        }

    def _finding_to_result(self, finding: Finding) -> dict[str, Any]:
        """Create a SARIF result from a Finding."""
        message_parts = [finding.title]
        if finding.description:
            message_parts.append(finding.description)

        # Include hashed PII from raw_data if present
        pii_keys = {"email", "username", "phone", "domain", "ip", "ip_address"}
        hashed_extras = {}
        for k, v in finding.raw_data.items():
            if k in pii_keys and isinstance(v, str):
                hashed_extras[f"{k}_hash"] = self._hash_value(v)

        result: dict[str, Any] = {
            "ruleId": f"{finding.module}/{finding.id}",
            "level": self._severity_to_result_level(finding.severity),
            "message": {"text": " | ".join(message_parts)},
            "properties": {
                "confidence": finding.confidence,
                "module": finding.module,
                "tags": finding.tags,
            },
        }

        if hashed_extras:
            result["properties"]["zkit_hashes"] = hashed_extras

        return result

    def _scan_to_invocations(self, result: ScanResult) -> dict[str, Any]:
        """Create a SARIF invocation entry from a ScanResult."""
        invocation: dict[str, Any] = {
            "executionSuccessful": result.status != "error",
            "toolExecutionNotifications": [],
        }
        if result.started_at and result.completed_at:
            invocation["startTimeUtc"] = result.started_at.isoformat()
            invocation["endTimeUtc"] = result.completed_at.isoformat()
        if result.error:
            invocation["toolExecutionNotifications"].append(
                {
                    "level": "error",
                    "message": {"text": result.error},
                }
            )
        return invocation

    def format(self, results: list[ScanResult]) -> str:
        """Format ScanResults into SARIF 2.1.0 JSON string.

        Args:
            results: List of ScanResult objects.
        Returns:
            SARIF 2.1.0 compliant JSON string.
        """
        import json

        # Collect all rules and results
        all_rules = []
        all_results = []
        all_invocations = []

        for scan in results:
            all_invocations.append(self._scan_to_invocations(scan))
            for finding in scan.findings:
                all_rules.append(self._finding_to_rule(finding))
                all_results.append(self._finding_to_result(finding))

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": "https://github.com/1ai-osint",
                            "rules": all_rules,
                        }
                    },
                    "results": all_results,
                    "invocations": all_invocations,
                    "properties": {
                        "zkit_mode": True,
                        "scan_count": len(results),
                        "total_findings": sum(r.finding_count for r in results),
                    },
                }
            ],
        }

        return json.dumps(sarif, indent=2, default=str)
