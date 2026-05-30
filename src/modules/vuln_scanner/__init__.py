"""Vulnerability Scanner module — infrastructure vulnerability assessment via scan4all."""

import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any

from src.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool

logger = logging.getLogger(__name__)

__all__ = ["VulnScannerTool"]

SUPPORTED_MODES = ("quick", "full", "fingerprint")


class VulnScannerTool(BaseOSINTTool):
    """Scan infrastructure for vulnerabilities using scan4all."""

    name = "vuln_scanner"
    description = (
        "Infrastructure vulnerability assessment (CVEs, fingerprints, port scanning)"
    )

    def __init__(self, binary_path: str = "scan4all"):
        self.binary_path = binary_path
        self._validate_binary()

    def _validate_binary(self) -> None:
        """Check that scan4all binary is available."""
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("scan4all binary found: %s", result.stdout.strip())
            else:
                logger.warning("scan4all binary returned non-zero exit code")
        except FileNotFoundError:
            logger.warning(
                "scan4all binary not found at '%s'. "
                "Install with: go install github.com/GhostTroops/scan4all@latest",
                self.binary_path,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Error checking scan4all binary: %s", exc)

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Quick vulnerability search — equivalent to mode='quick'."""
        return await self.scan(query, mode="quick", **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Run scan4all against the target and return findings.

        Args:
            target: Hostname, IP, or URL to scan.
            **kwargs: Additional options:
                mode: Scan mode — 'quick', 'full', or 'fingerprint'.
                timeout: Per-host timeout in seconds.
        """
        mode = kwargs.get("mode", "quick")
        timeout = kwargs.get("timeout", 300)
        started_at = datetime.now(timezone.utc)
        findings = self._run_scan(target, mode=mode, timeout=timeout)
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: dict[str, Any], **kwargs) -> dict[str, Any]:
        """Analyze vulnerability data — delegates to scan."""
        target = data.get("target", "")
        result = await self.scan(target, **kwargs)
        return {"findings_count": len(result.findings), "target": target}

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Learn from scan results (not implemented)."""
        raise NotImplementedError("VulnScannerTool does not support learning")

    def _run_scan(
        self, target: str, mode: str = "quick", timeout: int = 300
    ) -> list[Finding]:
        """Execute scan4all and parse results.

        Args:
            target: Host/IP/URL to scan.
            mode: One of 'quick', 'full', 'fingerprint'.
            timeout: Process timeout in seconds.

        Returns:
            List of Finding objects for discovered vulnerabilities.
        """
        if mode not in SUPPORTED_MODES:
            raise ValueError(
                f"Unsupported mode: {mode!r}. Choose from {SUPPORTED_MODES}"
            )

        cmd = self._build_command(target, mode)
        logger.info("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("scan4all timed out after %ds for target %s", timeout, target)
            return []
        except FileNotFoundError:
            logger.error("scan4all binary not found at '%s'", self.binary_path)
            return []

        findings = self._parse_output(result.stdout, target)
        if result.stderr:
            logger.debug("scan4all stderr: %s", result.stderr[:500])
        return findings

    def _build_command(self, target: str, mode: str) -> list[str]:
        """Build the scan4all command-line arguments.

        Args:
            target: Host/IP/URL to scan.
            mode: Scan mode.

        Returns:
            Command as a list of strings.
        """
        cmd = [self.binary_path, "-t", target]

        if mode == "quick":
            cmd.extend(["-scan", "pocv2", "-fingerprinthash", "true"])
        elif mode == "full":
            cmd.extend(["-scan", "pocv2,portscan,fingerprinthash"])
        elif mode == "fingerprint":
            cmd.extend(["-scan", "fingerprinthash"])

        return cmd

    def _parse_output(self, stdout: str, target: str) -> list[Finding]:
        """Parse scan4all JSON output into Finding objects.

        scan4all outputs JSON lines, one per vulnerability found.

        Args:
            stdout: Raw stdout from scan4all.
            target: The target that was scanned.

        Returns:
            List of Finding objects.
        """
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                vuln = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON line: %s", line[:100])
                continue

            finding = Finding(
                id=str(uuid.uuid4()),
                module=self.name,
                title=vuln.get("name", vuln.get("vuln_id", "Unknown vulnerability")),
                description=vuln.get("description", vuln.get("detail", "")),
                severity=self._map_severity(vuln.get("severity", "")),
                confidence=0.8,
                raw_data=vuln,
                timestamp=now,
                tags=["vulnerability", "infrastructure", _mode_tag(vuln)],
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _map_severity(severity: str) -> Severity:
        """Map scan4all severity to our Severity enum."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(severity.lower(), Severity.INFO)


def _mode_tag(vuln: dict) -> str:
    """Extract a mode tag from a vulnerability dict."""
    vuln_type = vuln.get("type", vuln.get("category", ""))
    if vuln_type:
        return str(vuln_type).lower().replace(" ", "_")
    return "unknown"
