"""Crypto private key scanner using GitHound integration.

Scans git repositories and file trees for leaked private keys in
WIF, hex, Base58, and PEM formats using subprocess-based detection.
"""

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool

# Regex patterns for private key formats
_PATTERNS: dict[str, re.Pattern] = {
    "wif": re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
    "hex_32byte": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "hex_0x": re.compile(r"\b0x[0-9a-fA-F]{64}\b"),
    "base58": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{44,88}\b"),
    "pem_private": re.compile(
        r"-----BEGIN (?:EC |RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:EC |RSA )?PRIVATE KEY-----",
        re.MULTILINE,
    ),
    "pem_encrypted": re.compile(
        r"-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]+?-----END ENCRYPTED PRIVATE KEY-----",
        re.MULTILINE,
    ),
}

_SEVERITY_MAP: dict[str, Severity] = {
    "wif": Severity.CRITICAL,
    "hex_32byte": Severity.CRITICAL,
    "hex_0x": Severity.CRITICAL,
    "base58": Severity.HIGH,
    "pem_private": Severity.CRITICAL,
    "pem_encrypted": Severity.HIGH,
}


def detect_key_format(text: str) -> list[dict[str, Any]]:
    """Scan raw text for private key patterns.

    Args:
        text: Raw text content to scan.

    Returns:
        List of dicts with keys: format, match, position, severity.

    """
    results = []
    for fmt, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            # Skip matches that are too short for hex in non-hex contexts
            matched_text = match.group(0)
            if fmt == "hex_32byte" and len(matched_text) != 64:
                continue
            results.append(
                {
                    "format": fmt,
                    "match": matched_text[:80],  # Truncate for safety
                    "position": match.start(),
                    "severity": _SEVERITY_MAP[fmt].value,
                }
            )
    return results


def scan_file(file_path: Path) -> list[dict[str, Any]]:
    """Scan a single file for private key patterns.

    Args:
        file_path: Path to the file to scan.

    Returns:
        List of detection results.

    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        results = detect_key_format(content)
        for r in results:
            r["file"] = str(file_path)
        return results
    except (OSError, PermissionError):
        return []


class PrivateKeyScanner(BaseOSINTTool):
    """Detect leaked crypto private keys in repos and file trees."""

    name = "crypto_privatekey"
    description = "Scan for leaked crypto private keys (WIF, hex, Base58, PEM)"
    version = "0.1.0"

    def __init__(
        self,
        githound_path: str = "githound",
        zkit_salt: str | None = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.githound_path = githound_path

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Search a repository path for private keys using GitHound.

        Args:
            query: Path to git repository.

        """
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan a repository or directory for private keys.

        Uses GitHound subprocess for git repos, falls back to
        regex scanning for plain directories.

        Args:
            target: Path to repository or directory.

        """
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        target_path = Path(target).resolve()
        if not target_path.exists():
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error=f"Path does not exist: {target}",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        # Try GitHound if it's a git repo
        if (target_path / ".git").exists():
            findings = await self._scan_with_githound(target_path, scan_id, **kwargs)
        else:
            findings = await self._scan_with_regex(target_path, scan_id)

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            metadata={
                "findings_count": len(findings),
                "scanner": "githound" if (target_path / ".git").exists() else "regex",
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def _scan_with_githound(self, repo_path: Path, scan_id: str, **kwargs) -> list[Finding]:
        """Run GitHound subprocess to detect keys in git history."""
        findings = []
        try:
            result = subprocess.run(
                [
                    self.githound_path,
                    "scan",
                    str(repo_path),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 300),
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    raw_findings = json.loads(result.stdout)
                    if isinstance(raw_findings, dict):
                        raw_findings = [raw_findings]
                    for raw in raw_findings:
                        finding = self._raw_to_finding(raw, scan_id)
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            # GitHound not installed, fall back to regex
            findings = await self._scan_with_regex(repo_path, scan_id)
        except subprocess.TimeoutExpired:
            pass

        return findings

    async def _scan_with_regex(self, target_path: Path, scan_id: str) -> list[Finding]:
        """Fallback regex-based scanning of files."""
        findings = []
        _SCAN_EXTENSIONS = {
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".jks",
            ".keystore",
            ".env",
            ".cfg",
            ".conf",
            ".config",
            ".ini",
            ".yml",
            ".yaml",
            ".json",
            ".xml",
            ".txt",
            ".sh",
            ".py",
            ".js",
            ".ts",
        }

        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            if any(part.startswith(".") and part not in {".env"} for part in file_path.relative_to(target_path).parts):
                # Skip hidden dirs except .env files
                if file_path.suffix != ".env":
                    continue

            detections = scan_file(file_path)
            for det in detections:
                sev = Severity(det["severity"])
                finding = Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Private key detected ({det['format']})",
                    description=f"Potential {det['format']} private key in {det.get('file', 'unknown')}",
                    severity=sev,
                    raw_data={
                        "format": det["format"],
                        "file": det.get("file", str(file_path)),
                        "position": det["position"],
                        "match_preview": det["match"],
                    },
                    confidence=0.7,
                    tags=["private_key", "crypto", det["format"]],
                )
                findings.append(finding)

        return findings

    def _raw_to_finding(self, raw: dict, scan_id: str) -> Finding | None:
        """Convert a GitHound JSON result to a Finding."""
        rule_id = raw.get("rule_id", raw.get("rule-id", "private-key"))
        severity = _SEVERITY_MAP.get(rule_id, Severity.HIGH)

        return Finding(
            id=self._make_finding_id(),
            module=self.name,
            title=f"Private key detected: {rule_id}",
            description=raw.get("description", ""),
            severity=severity,
            raw_data={
                "rule_id": rule_id,
                "file": raw.get("file", raw.get("File", "")),
                "line": raw.get("line", raw.get("Line", "")),
                "match": raw.get("match", raw.get("Match", ""))[:100],
                "commit": raw.get("commit", raw.get("Commit", "")),
                "author": raw.get("author", raw.get("Author", "")),
            },
            confidence=0.85,
            tags=["private_key", "crypto", "githound", rule_id],
        )

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze private key findings for patterns."""
        if isinstance(data, ScanResult):
            findings = data.findings
        elif isinstance(data, list):
            findings = data
        else:
            return {"error": "Unsupported data type"}

        format_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for f in findings:
            fmt = f.raw_data.get("format", "unknown")
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_findings": len(findings),
            "format_breakdown": format_counts,
            "severity_breakdown": severity_counts,
            "has_critical": any(f.severity == Severity.CRITICAL for f in findings),
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Accept feedback on false positives."""
        pass
