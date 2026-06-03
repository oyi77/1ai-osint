"""SARIF 2.1.0 formatting for CLI scan results."""

import json


def format_sarif(results: list) -> str:
    """Format scan results as SARIF 2.1.0."""
    sarif_runs = []
    all_rules = []
    all_results = []

    for scan_result in results:
        for finding in scan_result.findings or []:
            rule_id = finding.id
            severity = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity)
            )

            # Map to SARIF level
            level = "none"
            if severity in ("critical", "high"):
                level = "error"
            elif severity == "medium":
                level = "warning"
            elif severity == "low":
                level = "note"

            all_rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": level},
                }
            )

            all_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": finding.description},
                    "properties": {
                        "module": finding.module,
                        "confidence": finding.confidence,
                        "tags": finding.tags,
                    },
                }
            )

    sarif_runs.append(
        {
            "tool": {
                "driver": {
                    "name": "1ai-osint",
                    "version": "0.1.0",
                    "rules": all_rules,
                }
            },
            "results": all_results,
        }
    )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": sarif_runs,
    }
    return json.dumps(sarif, indent=2, default=str)
