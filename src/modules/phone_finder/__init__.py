"""Phone Finder module: Phone number OSINT (PhoneInfoga)."""

from typing import Any

import httpx

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.modules.phone_finder.lookup import PhoneFinderLookup

__all__ = ["PhoneFinderTool", "PhoneFinderLookup"]


class PhoneFinderTool(BaseOSINTTool):
    """Lookup phone number carrier, location, and linked accounts."""

    name = "phone_finder"
    description = "Phone number OSINT: carrier, location, and linked account lookup"
    version = "0.1.0"

    def __init__(
        self,
        phoneinfoga_url: str | None = None,
        zkit_salt: str | None = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.phoneinfoga_url = phoneinfoga_url or "http://localhost:3000"

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Search for phone number information."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Full phone OSINT scan via PhoneInfoga API or NumVerify fallback."""
        scan_id = self._make_scan_id()
        from datetime import datetime, timezone

        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        # Clean phone number
        from src.utils.phone_normalize import normalize_phone_e164

        normalized = normalize_phone_e164(target, default_region="ID")
        phone = normalized or target

        # Try PhoneInfoga API
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{self.phoneinfoga_url}/api/v1/numbers/{phone}")
                if resp.status_code == 200:
                    data = resp.json()
                    number_info = data.get("number", data)

                    findings.append(
                        Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Phone info: {phone}",
                            description=f"Phone number {phone} lookup results",
                            severity=Severity.INFO,
                            raw_data=number_info,
                            confidence=0.9,
                            tags=["phone", "carrier"],
                        )
                    )

                    # Check for scam/fraud reports
                    scanner_results = number_info.get("scanners", [])
                    for scanner in scanner_results:
                        if scanner.get("found"):
                            findings.append(
                                Finding(
                                    id=self._make_finding_id(),
                                    module=self.name,
                                    title=f"Scam report: {phone}",
                                    description=f"Number reported as scam/fraud by {scanner.get('name', 'unknown')}",
                                    severity=Severity.HIGH,
                                    raw_data=scanner,
                                    confidence=0.7,
                                    tags=["phone", "scam", "fraud"],
                                )
                            )

                    return ScanResult(
                        scan_id=scan_id,
                        module=self.name,
                        target=target,
                        status="ok",
                        findings=findings,
                        metadata={"phone": phone, "tool": "phoneinfoga"},
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc),
                    )
        except (httpx.RequestError, httpx.TimeoutException):
            pass  # Fall through to basic validation

        # Fallback: basic number validation via NumVerify or similar.
        # Only emit a record when the target actually normalizes as a phone
        # number; otherwise this would fabricate findings for arbitrary input
        # (e.g. a username) whenever PhoneInfoga is unreachable.
        if not normalized:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="partial",
                findings=[],
                metadata={
                    "phone": None,
                    "tool": "basic",
                    "note": "Target is not a valid phone number; PhoneInfoga unreachable",
                },
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        findings.append(
            Finding(
                id=self._make_finding_id(),
                module=self.name,
                title=f"Phone number: {phone}",
                description=f"PhoneInfoga unavailable. Basic record for {phone}",
                severity=Severity.INFO,
                raw_data={"phone": phone, "validated": False},
                confidence=0.3,
                tags=["phone", "basic"],
            )
        )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="partial",
            findings=findings,
            metadata={
                "phone": phone,
                "tool": "basic",
                "note": "PhoneInfoga unavailable",
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze carrier, VoIP status, anomalies."""
        if isinstance(data, ScanResult):
            findings = data.findings
        elif isinstance(data, list):
            findings = data
        else:
            return {"error": "Unsupported data type"}

        has_scam = any("scam" in f.tags or "fraud" in f.tags for f in findings)

        return {
            "total_findings": len(findings),
            "has_scam_reports": has_scam,
            "phone": data.target if isinstance(data, ScanResult) else "unknown",
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Improve carrier detection heuristics."""
        pass
