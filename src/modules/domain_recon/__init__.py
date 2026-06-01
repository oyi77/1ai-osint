"""Domain Reconnaissance module for comprehensive domain analysis."""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from src.modules.base.base import BaseOSINTTool
from src.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class DomainReconTool(BaseOSINTTool):
    """Comprehensive domain reconnaissance tool.

    Performs WHOIS lookup, DNS enumeration, subdomain discovery,
    certificate transparency analysis, and tech stack detection.
    """

    name = "domain_recon"

    def __init__(self, **kwargs: Any):
        self.timeout = kwargs.pop("timeout", 30)
        super().__init__(**kwargs)

    async def search(self, query: str, **kwargs: Any) -> ScanResult:
        """Search for domain information."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Perform comprehensive domain reconnaissance."""
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        try:
            # Run all recon tasks concurrently
            results = await asyncio.gather(
                self._whois_lookup(target),
                self._dns_enumeration(target),
                self._subdomain_discovery(target),
                self._certificate_transparency(target),
                self._tech_stack_detection(target),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Recon task failed: %s", result)
                    continue
                if isinstance(result, Finding):
                    findings.append(result)

        except Exception as exc:
            logger.error("Domain recon failed: %s", exc)
            results = []

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            metadata={
                "target": target,
                "tasks_completed": len([r for r in results if not isinstance(r, Exception)]),
                "tasks_failed": len([r for r in results if isinstance(r, Exception)]),
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: Any, **kwargs: Any) -> dict[str, Any]:
        """Analyze domain recon results."""
        if isinstance(data, ScanResult):
            return {
                "total_findings": data.finding_count,
                "critical": data.critical_count,
                "domains_analyzed": data.metadata.get("domains_analyzed", 0),
            }
        return {}

    async def learn(self, feedback: Any, **kwargs: Any) -> None:
        """Learn from feedback (no-op for now)."""
        pass

    async def _whois_lookup(self, domain: str) -> Finding | None:
        """Perform WHOIS lookup."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://whois.arin.net/rest/domain/{domain}")
                if resp.status_code == 200:
                    return Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        title=f"WHOIS Record for {domain}",
                        description=resp.text[:1000],
                        severity=Severity.INFO,
                        raw_data={"type": "whois", "domain": domain, "data": resp.text[:5000]},
                    )
        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None

    async def _dns_enumeration(self, domain: str) -> Finding | None:
        """Enumerate DNS records."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://dns.google/resolve?name={domain}&type=ANY")
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    if answers:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"DNS Records for {domain}",
                            description=f"Found {len(answers)} DNS records",
                            severity=Severity.INFO,
                            raw_data={"type": "dns", "domain": domain, "records": answers},
                        )
        except Exception as exc:
            logger.debug("DNS enumeration failed for %s: %s", domain, exc)
        return None

    async def _subdomain_discovery(self, domain: str) -> Finding | None:
        """Discover subdomains via crt.sh."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip()
                            if sub and "*" not in sub:
                                subdomains.add(sub)
                    if subdomains:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Subdomains Discovered for {domain}",
                            description=f"Found {len(subdomains)} unique subdomains",
                            severity=Severity.INFO,
                            raw_data={"type": "subdomains", "domain": domain, "subdomains": sorted(subdomains)},
                        )
        except Exception as exc:
            logger.debug("Subdomain discovery failed for %s: %s", domain, exc)
        return None

    async def _certificate_transparency(self, domain: str) -> Finding | None:
        """Check certificate transparency logs."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://crt.sh/?q={domain}&output=json")
                if resp.status_code == 200:
                    data = resp.json()
                    if data:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Certificate Transparency for {domain}",
                            description=f"Found {len(data)} certificates",
                            severity=Severity.INFO,
                            raw_data={"type": "ct_logs", "domain": domain, "certificates": data[:10]},
                        )
        except Exception as exc:
            logger.debug("Certificate transparency check failed for %s: %s", domain, exc)
        return None

    async def _tech_stack_detection(self, domain: str) -> Finding | None:
        """Detect technology stack via HTTP headers."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(f"https://{domain}")
                headers = dict(resp.headers)
                tech_indicators = {}

                # Server header
                if "server" in headers:
                    tech_indicators["server"] = headers["server"]

                # X-Powered-By
                if "x-powered-by" in headers:
                    tech_indicators["powered_by"] = headers["x-powered-by"]

                # Content-Security-Policy
                if "content-security-policy" in headers:
                    tech_indicators["csp"] = True

                # X-Frame-Options
                if "x-frame-options" in headers:
                    tech_indicators["xframe"] = headers["x-frame-options"]

                if tech_indicators:
                    return Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        title=f"Technology Stack for {domain}",
                        description=f"Detected {len(tech_indicators)} technology indicators",
                        severity=Severity.INFO,
                        raw_data={"type": "tech_stack", "domain": domain, "indicators": tech_indicators},
                    )
        except Exception as exc:
            logger.debug("Tech stack detection failed for %s: %s", domain, exc)
        return None
