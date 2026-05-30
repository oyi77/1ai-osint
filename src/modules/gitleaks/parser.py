"""Parser for gitleaks JSON output into Finding models."""

import json

from src.models import Finding, Severity


def parse_gitleaks_json(raw_json: str | list | dict) -> list[Finding]:
    """
    Parse gitleaks JSON output into a list of Finding models.

    Args:
        raw_json: gitleaks JSON output (string, list, or dict)
    Returns:
        List of Finding objects
    """
    if isinstance(raw_json, str):
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []
    else:
        data = raw_json

    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        return []

    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue

        rule_id = item.get("rule-id", item.get("RuleID", "unknown"))
        description = item.get("description", item.get("Description", ""))

        # Map severity based on rule ID
        severity = _classify_severity(rule_id)

        finding = Finding(
            id=f"gitleaks-{rule_id}-{item.get('file', 'unknown')}",
            module="gitleaks",
            title=f"Secret: {rule_id}",
            description=description,
            severity=severity,
            raw_data={
                "rule_id": rule_id,
                "file": item.get("file", item.get("File", "")),
                "line": item.get("line", item.get("Line", "")),
                "match": item.get("match", item.get("Match", ""))[:200],
                "commit": item.get("commit", item.get("Commit", "")),
                "author": item.get("author", item.get("Author", "")),
                "email": item.get("email", item.get("Email", "")),
                "date": item.get("date", item.get("Date", "")),
            },
            confidence=0.9,
            tags=["secret", "gitleaks", rule_id],
        )
        findings.append(finding)

    return findings


def _classify_severity(rule_id: str) -> Severity:
    """Classify severity based on gitleaks rule ID."""
    critical_rules = {
        "aws-access-token", "aws-secret-key", "github-token",
        "gitlab-token", "private-key", "pkcs8-private-key",
    }
    high_rules = {
        "generic-api-key", "generic-password", "slack-token",
        "stripe-access-token", "npm-token", "pypi-upload-token",
    }

    if rule_id in critical_rules:
        return Severity.CRITICAL
    if rule_id in high_rules:
        return Severity.HIGH
    return Severity.MEDIUM
