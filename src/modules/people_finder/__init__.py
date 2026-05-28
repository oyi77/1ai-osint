"""People Finder module: Social media username search (Sherlock/Maigret/WhatsMyName)."""

import asyncio
import subprocess
import shutil
from typing import Any, Optional

from src.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.modules.people_finder.search import PeopleFinderSearch

__all__ = ["PeopleFinderTool", "PeopleFinderSearch"]


class PeopleFinderTool(BaseOSINTTool):
    """Search for user profiles across social media platforms."""

    name = "people_finder"
    description = "Search for usernames across social media platforms using Sherlock/Maigret"
    version = "0.1.0"

    def __init__(
        self,
        sherlock_path: str = "sherlock",
        maigret_path: str = "maigret",
        zkit_salt: Optional[str] = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.sherlock_path = sherlock_path
        self.maigret_path = maigret_path

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Search for username across social platforms using sherlock."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan for all matching profiles using sherlock."""
        scan_id = self._make_scan_id()
        from datetime import datetime
        started_at = datetime.utcnow()
        findings: list[Finding] = []
        errors: list[str] = []

        # Try sherlock first, fall back to maigret
        tool = self._pick_tool()
        if not tool:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error="Neither sherlock nor maigret found. Install with: pip install sherlock-project",
                started_at=started_at,
                completed_at=datetime.utcnow(),
            )

        try:
            cmd = [tool, target, "--print-found", "--output", "json", "--json", "-"]
            if tool == self.maigret_path:
                cmd = [tool, target, "--json", "simple"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 120),
                check=False,
            )

            if result.stdout.strip():
                import json
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        for site, info in data.items():
                            if isinstance(info, dict) and info.get("status") == "Claimed":
                                findings.append(Finding(
                                    id=self._make_finding_id(),
                                    module=self.name,
                                    title=f"Profile found: {target} on {site}",
                                    description=f"Username '{target}' found on {site}",
                                    severity=Severity.LOW,
                                    raw_data={"site": site, "url": info.get("url", ""), "username": target},
                                    confidence=0.8,
                                    tags=["people", "social", site.lower()],
                                ))
                except json.JSONDecodeError:
                    # Line-based output parsing
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if line.startswith("http"):
                            findings.append(Finding(
                                id=self._make_finding_id(),
                                module=self.name,
                                title=f"Profile found: {target}",
                                description=line,
                                severity=Severity.LOW,
                                raw_data={"url": line, "username": target},
                                confidence=0.7,
                                tags=["people", "social"],
                            ))

            if result.returncode not in (0, 1):
                errors.append(f"{tool} exited with code {result.returncode}: {result.stderr}")

        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error="People finder scan timed out",
                started_at=started_at,
                completed_at=datetime.utcnow(),
            )
        except FileNotFoundError:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error=f"Tool '{tool}' not found. Install with: pip install sherlock-project",
                started_at=started_at,
                completed_at=datetime.utcnow(),
            )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok" if not errors else "partial",
            findings=findings,
            metadata={"tool": tool, "findings_count": len(findings), "errors": errors},
            started_at=started_at,
            completed_at=datetime.utcnow(),
        )

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Deduplicate and correlate profiles."""
        if isinstance(data, ScanResult):
            findings = data.findings
        elif isinstance(data, list):
            findings = data
        else:
            return {"error": "Unsupported data type"}

        sites = {}
        for f in findings:
            site = f.raw_data.get("site", "unknown")
            sites[site] = sites.get(site, 0) + 1

        return {
            "total_profiles": len(findings),
            "sites_found": sites,
            "username": data.target if isinstance(data, ScanResult) else "unknown",
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Improve profile matching heuristics."""
        pass

    def _pick_tool(self) -> Optional[str]:
        """Pick the first available tool."""
        if shutil.which(self.sherlock_path):
            return self.sherlock_path
        if shutil.which(self.maigret_path):
            return self.maigret_path
        return None