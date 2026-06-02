"""Report Engine — standalone report generation and input parsing.

Can generate reports from ANY module's ScanResult, and can parse
existing reports to extract identifiers for new scans.
"""
from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from src.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    PDF = "pdf"


@dataclass
class ReportSection:
    """A section of the report (e.g., Emails, Usernames, Findings)."""
    title: str
    items: list[str | dict[str, Any]]
    severity: Optional[str] = None
    icon: str = ""


@dataclass
class ReportData:
    """Structured report data that can be generated from any ScanResult."""
    target: str
    title: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sections: list[ReportSection] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_results: list[ScanResult] = field(default_factory=list)
    identifiers: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    def add_section(self, title: str, items: list, icon: str = "") -> None:
        self.sections.append(ReportSection(title=title, items=items, icon=icon))

    def add_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "sections": [
                {"title": s.title, "items": s.items, "severity": s.severity, "icon": s.icon}
                for s in self.sections
            ],
            "findings": [
                {
                    "id": f.id, "module": f.module, "title": f.title,
                    "description": f.description, "severity": f.severity.value,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "identifiers": self.identifiers,
            "metadata": self.metadata,
        }


class ReportEngine:
    """Generate and parse reports from any module's results."""

    def from_scan_results(self, target: str, results: list[ScanResult]) -> ReportData:
        """Generate report data from multiple ScanResults."""
        report = ReportData(
            target=target,
            title=f"OSINT Report: {target}",
        )

        all_emails: set[str] = set()
        all_usernames: set[str] = set()
        all_phones: set[str] = set()
        all_domains: set[str] = set()
        all_ips: set[str] = set()
        all_crypto: set[str] = set()
        all_findings: list[Finding] = []

        for sr in results:
            report.scan_results.append(sr)
            all_findings.extend(sr.findings)

            # Extract identifiers from findings
            for finding in sr.findings:
                raw = finding.raw_data or {}
                text = str(raw)

                # Emails
                for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
                    all_emails.add(m.group())

                # Usernames
                for m in re.finditer(r"(?<!\w)@([a-zA-Z0-9_]{3,30})(?!\w)", text):
                    all_usernames.add(m.group(1))

                # Phones
                for m in re.finditer(r"(?:\+?62|0)[\s-]?[0-9]{8,13}", text):
                    all_phones.add(m.group())

                # Domains
                for m in re.finditer(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}", text):
                    all_domains.add(m.group())

                # IPs
                for m in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text):
                    all_ips.add(m.group())

                # Crypto addresses
                for m in re.finditer(r"0x[a-fA-F0-9]{40}", text):
                    all_crypto.add(m.group())

        # Add sections
        if all_emails:
            report.add_section("Emails", sorted(all_emails), "📧")
        if all_usernames:
            report.add_section("Usernames", sorted(all_usernames), "👤")
        if all_phones:
            report.add_section("Phones", sorted(all_phones), "📱")
        if all_domains:
            report.add_section("Domains", sorted(all_domains), "🌐")
        if all_ips:
            report.add_section("IP Addresses", sorted(all_ips), "🔗")
        if all_crypto:
            report.add_section("Crypto Addresses", sorted(all_crypto), "💰")

        report.add_findings(all_findings)

        # Store identifiers for report-to-scan input
        report.identifiers = [
            {"value": e, "type": "email"} for e in all_emails
        ] + [
            {"value": u, "type": "username"} for u in all_usernames
        ] + [
            {"value": p, "type": "phone"} for p in all_phones
        ] + [
            {"value": d, "type": "domain"} for d in all_domains
        ] + [
            {"value": i, "type": "ip"} for i in all_ips
        ] + [
            {"value": c, "type": "crypto_address"} for c in all_crypto
        ]

        report.metadata = {
            "scan_count": len(results),
            "total_findings": len(all_findings),
            "critical_findings": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            "sources_used": list({sr.module for sr in results}),
        }

        return report

    def parse_report_json(self, json_str: str) -> ReportData:
        """Parse a JSON report back into ReportData for re-scanning."""
        data = json.loads(json_str)
        report = ReportData(
            target=data.get("target", ""),
            title=data.get("title", ""),
        )
        report.identifiers = data.get("identifiers", [])
        report.metadata = data.get("metadata", {})
        return report

    def extract_identifiers_for_scan(self, report: ReportData) -> list[dict[str, str]]:
        """Extract identifiers from a report that can be used as scan inputs."""
        return [
            {"value": ident["value"], "type": ident["type"]}
            for ident in report.identifiers
            if ident.get("value")
        ]
