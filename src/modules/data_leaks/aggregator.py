"""Multi-source data leak aggregation module."""

import asyncio
import uuid
from datetime import datetime
from typing import Any, Optional

from src.models import BreachRecord, Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.modules.data_leaks.breach_checker import BreachChecker


class DataLeaksAggregator(BaseOSINTTool):
    """
    Aggregates breach/leak data from multiple sources.

    Sources include vendored chiasmodon providers (HIBP, LeakCheck, Scylla, etc.)
    and the BreachChecker for severity scoring.
    """

    name = "data_leaks"
    description = "Multi-source data leak aggregation and breach checking"
    version = "0.1.0"

    def __init__(
        self,
        zkit_salt: Optional[str] = None,
        providers: Optional[list[str]] = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self._requested_providers = providers
        self._checker = BreachChecker()
        self._false_positives: list[dict] = []

    def _get_providers(self) -> dict[str, Any]:
        """Get available leak check providers."""
        available = {}
        try:
            from src.vendor.chiasmodon.hibp import HIBPTool
            available["hibp"] = HIBPTool()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.leak_leakcheck import LeakCheckTool
            available["leakcheck"] = LeakCheckTool()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.leak_scylla import ScyllaTool
            available["scylla"] = ScyllaTool()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.leak_breachdirectory import BreachDirectoryTool
            available["breachdirectory"] = BreachDirectoryTool()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.leak_snusbase import SnusbaseTool
            available["snusbase"] = SnusbaseTool()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.leak_intelx import IntelXTool
            available["intelx"] = IntelXTool()
        except ImportError:
            pass

        if self._requested_providers:
            return {k: v for k, v in available.items() if k in self._requested_providers}
        return available

    async def search(self, query: str, **kwargs) -> ScanResult:
        """
        Search for breaches/leaks across all providers.

        Args:
            query: Email, username, or domain to search
        """
        scan_id = self._make_scan_id()
        started_at = datetime.utcnow()
        breach_records: list[BreachRecord] = []
        findings: list[Finding] = []
        errors: dict[str, str] = {}

        providers = self._get_providers()

        # Run all provider searches concurrently
        tasks = []
        for name, provider in providers.items():
            tasks.append(self._query_provider(name, provider, query))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for provider_name, result in zip(providers.keys(), results):
            if isinstance(result, Exception):
                errors[provider_name] = str(result)
                continue
            if isinstance(result, dict) and result.get("status") == "error":
                errors[provider_name] = result.get("error", "Unknown error")
                continue

            # Parse provider results into BreachRecords
            records = self._parse_provider_results(provider_name, result)
            breach_records.extend(records)

        # Deduplicate
        breach_records = self._deduplicate(breach_records)

        # Score severity
        for record in breach_records:
            record.severity = self._checker.score_severity(record)

        # Remove false positives
        breach_records = self._filter_false_positives(breach_records)

        # Convert high-severity breaches to findings
        for record in breach_records:
            if record.severity in (Severity.CRITICAL, Severity.HIGH):
                findings.append(Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Breach: {record.source} - {record.email or record.username}",
                    description=record.description,
                    severity=record.severity,
                    raw_data=record.model_dump(exclude_none=True),
                    confidence=0.85,
                    tags=["breach", "leak", record.source],
                ))

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=query,
            status="ok" if not errors else "partial",
            findings=findings,
            breach_records=breach_records,
            metadata={
                "providers_queried": list(providers.keys()),
                "providers_errored": errors,
                "total_records": len(breach_records),
                "deduplicated_records": len(breach_records),
            },
            started_at=started_at,
            completed_at=datetime.utcnow(),
        )

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Alias for search."""
        return await self.search(target, **kwargs)

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze aggregated breach data."""
        if isinstance(data, ScanResult):
            records = data.breach_records
            findings = data.findings
        else:
            return {"error": "Unsupported data type"}

        source_counts = {}
        severity_counts = {}
        domains: dict[str, int] = {}

        for r in records:
            source_counts[r.source] = source_counts.get(r.source, 0) + 1
            sev = r.severity.value if hasattr(r.severity, "value") else str(r.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if r.domain:
                domains[r.domain] = domains.get(r.domain, 0) + 1

        return {
            "total_records": len(records),
            "total_findings": len(findings),
            "source_breakdown": source_counts,
            "severity_breakdown": severity_counts,
            "top_domains": dict(sorted(domains.items(), key=lambda x: -x[1])[:10]),
            "has_critical": any(r.severity == Severity.CRITICAL for r in records),
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Learn from feedback to improve false positive filtering."""
        if "false_positives" in feedback:
            self._false_positives.extend(feedback["false_positives"])
        if "false_negatives" in feedback:
            # Future: adjust scoring weights
            pass

    async def _query_provider(self, name: str, provider: Any, query: str) -> dict:
        """Query a single provider (runs in thread pool for sync providers)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, provider.search, query)

    def _parse_provider_results(self, provider_name: str, result: Any) -> list[BreachRecord]:
        """Parse a provider's raw result into BreachRecords."""
        records = []

        if isinstance(result, dict):
            if result.get("status") == "error":
                return records
            result_data = result.get("result", result.get("results", []))
        elif isinstance(result, list):
            result_data = result
        else:
            return records

        if not isinstance(result_data, list):
            result_data = [result_data]

        for item in result_data:
            if not isinstance(item, dict):
                continue
            record = BreachRecord(
                source=provider_name,
                email=item.get("email") or item.get("Email"),
                username=item.get("username") or item.get("Username"),
                domain=item.get("domain") or item.get("Domain") or item.get("source"),
                description=item.get("description") or item.get("Description", ""),
                data_classes=item.get("data_classes") or item.get("DataClasses") or [],
                raw=item,
            )
            records.append(record)

        return records

    def _deduplicate(self, records: list[BreachRecord]) -> list[BreachRecord]:
        """Deduplicate breach records by email+source."""
        seen: set[str] = set()
        deduped = []
        for r in records:
            key = f"{r.email or r.username}:{r.source}"
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        return deduped

    def _filter_false_positives(self, records: list[BreachRecord]) -> list[BreachRecord]:
        """Remove known false positives."""
        fp_set = {(fp.get("email"), fp.get("username")) for fp in self._false_positives}
        return [
            r for r in records
            if (r.email, r.username) not in fp_set
        ]
