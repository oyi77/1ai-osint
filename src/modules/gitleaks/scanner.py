"""Gitleaks/secret scanning module using GitHound subprocess wrapper."""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool

# Severity mapping for gitleaks rule IDs
_SEVERITY_MAP = {
    "aws-access-token": Severity.CRITICAL,
    "aws-secret-key": Severity.CRITICAL,
    "github-token": Severity.CRITICAL,
    "gitlab-token": Severity.CRITICAL,
    "private-key": Severity.CRITICAL,
    "generic-api-key": Severity.HIGH,
    "generic-password": Severity.HIGH,
    "slack-token": Severity.HIGH,
    "stripe-access-token": Severity.HIGH,
    "google-api-key": Severity.MEDIUM,
    "heroku-api-key": Severity.MEDIUM,
    "mailgun-api-key": Severity.MEDIUM,
    "sendgrid-api-key": Severity.MEDIUM,
    "twilio-api-key": Severity.MEDIUM,
}


class GitleaksModule(BaseOSINTTool):
    """Secret scanning module using gitleaks subprocess."""

    name = "gitleaks"
    description = "Scan git repositories for secrets and credentials"
    version = "0.1.0"

    def __init__(
        self,
        gitleaks_path: str = "gitleaks",
        zkit_salt: Optional[str] = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.gitleaks_path = gitleaks_path

    async def search(self, query: str, **kwargs) -> ScanResult:
        """
        Scan a git repo path for secrets.

        Args:
            query: Path to git repository
        """
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run gitleaks scan on a git repository.

        Args:
            target: Path to git repository directory
        """
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        repo_path = Path(target).resolve()
        if not repo_path.exists():
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error=f"Path does not exist: {target}",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        try:
            result = subprocess.run(
                [
                    self.gitleaks_path,
                    "detect",
                    "--source",
                    str(repo_path),
                    "--format",
                    "json",
                    "--no-banner",
                    "--no-color",
                ],
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 300),
                check=False,
            )

            # gitleaks exits 1 when secrets found, 0 when clean
            if result.returncode not in (0, 1):
                return ScanResult(
                    scan_id=scan_id,
                    module=self.name,
                    target=target,
                    status="error",
                    error=f"gitleaks exited with code {result.returncode}: {result.stderr}",
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                )

            # Parse JSON output
            raw_findings = []
            if result.stdout.strip():
                try:
                    raw_findings = json.loads(result.stdout)
                    if isinstance(raw_findings, dict):
                        raw_findings = [raw_findings]
                except json.JSONDecodeError:
                    # Try line-delimited JSON
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if line:
                            try:
                                parsed = json.loads(line)
                                if isinstance(parsed, list):
                                    raw_findings.extend(parsed)
                                elif isinstance(parsed, dict):
                                    raw_findings.append(parsed)
                            except json.JSONDecodeError:
                                continue

            for raw in raw_findings:
                rule_id = raw.get("rule-id", raw.get("RuleID", "unknown"))
                finding = Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Secret detected: {rule_id}",
                    description=raw.get("description", raw.get("Description", "")),
                    severity=_SEVERITY_MAP.get(rule_id, Severity.MEDIUM),
                    raw_data={
                        "rule_id": rule_id,
                        "file": raw.get("file", raw.get("File", "")),
                        "line": raw.get("line", raw.get("Line", "")),
                        "match": raw.get("match", raw.get("Match", ""))[:100],  # Truncate
                        "commit": raw.get("commit", raw.get("Commit", "")),
                        "author": raw.get("author", raw.get("Author", "")),
                        "email": raw.get("email", raw.get("Email", "")),
                        "date": raw.get("date", raw.get("Date", "")),
                    },
                    confidence=0.9,
                    tags=["secret", "gitleaks", rule_id],
                )
                findings.append(finding)

            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="ok",
                findings=findings,
                metadata={
                    "tool": self.gitleaks_path,
                    "findings_count": len(findings),
                },
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error="gitleaks scan timed out",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )
        except FileNotFoundError:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error=f"gitleaks not found at '{self.gitleaks_path}'. Install with: brew install gitleaks",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze gitleaks findings for patterns."""
        if isinstance(data, ScanResult):
            findings = data.findings
        elif isinstance(data, list):
            findings = data
        else:
            return {"error": "Unsupported data type"}

        severity_counts: dict[str, int] = {}
        rule_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            rule = f.raw_data.get("rule_id", "unknown")
            rule_counts[rule] = rule_counts.get(rule, 0) + 1

        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "rule_breakdown": rule_counts,
            "has_critical": any(f.severity == Severity.CRITICAL for f in findings),
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Accept feedback on false positives."""
        # Future: maintain a local allowlist
        pass
