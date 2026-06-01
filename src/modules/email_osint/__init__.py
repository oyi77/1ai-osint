"""Email OSINT module for comprehensive email analysis."""
from __future__ import annotations
import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from src.modules.base.base import BaseOSINTTool
from src.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class EmailOSINTTool(BaseOSINTTool):
    """Comprehensive email intelligence tool.

    Performs email validation, breach checking, social media lookup,
    domain analysis, and credential leak detection.
    """

    name = "email_osint"

    def __init__(self, **kwargs: Any):
        self.timeout = kwargs.pop("timeout", 30)
        super().__init__(**kwargs)

    async def search(self, query: str, **kwargs: Any) -> ScanResult:
        """Search for email intelligence."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Perform comprehensive email OSINT."""
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        if not _EMAIL_RE.match(target):
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error="Invalid email format",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        try:
            results = await asyncio.gather(
                self._validate_email(target),
                self._check_breaches(target),
                self._check_social_media(target),
                self._analyze_domain(target),
                self._check_disposable(target),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Email OSINT task failed: %s", result)
                    continue
                if isinstance(result, Finding):
                    findings.append(result)

        except Exception as exc:
            logger.error("Email OSINT failed: %s", exc)

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            metadata={
                "email": target,
                "domain": target.split("@")[1],
                "tasks_completed": len([r for r in results if not isinstance(r, Exception)]),
                "tasks_failed": len([r for r in results if isinstance(r, Exception)]),
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: Any, **kwargs: Any) -> dict[str, Any]:
        """Analyze email OSINT results."""
        if isinstance(data, ScanResult):
            return {
                "total_findings": data.finding_count,
                "critical": data.critical_count,
                "email": data.metadata.get("email", ""),
                "domain": data.metadata.get("domain", ""),
            }
        return {}

    async def learn(self, feedback: Any, **kwargs: Any) -> None:
        """Learn from feedback (no-op for now)."""
        pass

    async def _validate_email(self, email: str) -> Finding | None:
        """Validate email format and check MX records."""
        try:
            domain = email.split("@")[1]
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://dns.google/resolve?name={domain}&type=MX")
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    if answers:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Email Validation: {email}",
                            description=f"Domain {domain} has {len(answers)} MX records",
                            severity=Severity.INFO,
                            raw_data={"type": "validation", "email": email, "mx_records": answers},
                        )
        except Exception as exc:
            logger.debug("Email validation failed for %s: %s", email, exc)
        return None

    async def _check_breaches(self, email: str) -> Finding | None:
        """Check if email appears in known breaches."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://haveibeenpwned.com/unifiedsearch/{email}")
                if resp.status_code == 200:
                    data = resp.json()
                    breaches = data.get("Breaches", [])
                    if breaches:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Breaches Found for {email}",
                            description=f"Email found in {len(breaches)} breaches",
                            severity=Severity.HIGH,
                            raw_data={"type": "breaches", "email": email, "breaches": breaches},
                        )
        except Exception as exc:
            logger.debug("Breach check failed for %s: %s", email, exc)
        return None

    async def _check_social_media(self, email: str) -> Finding | None:
        """Check social media presence."""
        try:
            username = email.split("@")[0]
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Check GitHub
                resp = await client.get(f"https://api.github.com/search/users?q={username}")
                if resp.status_code == 200:
                    data = resp.json()
                    users = data.get("items", [])
                    if users:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Social Media Found for {email}",
                            description=f"Found {len(users)} potential GitHub matches",
                            severity=Severity.INFO,
                            raw_data={"type": "social", "email": email, "github_users": users[:5]},
                        )
        except Exception as exc:
            logger.debug("Social media check failed for %s: %s", email, exc)
        return None

    async def _analyze_domain(self, email: str) -> Finding | None:
        """Analyze the email domain."""
        try:
            domain = email.split("@")[1]
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://dns.google/resolve?name={domain}&type=TXT")
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    txt_records = [a.get("data", "") for a in answers if a.get("type") == 16]
                    if txt_records:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Domain Analysis for {domain}",
                            description=f"Found {len(txt_records)} TXT records",
                            severity=Severity.INFO,
                            raw_data={"type": "domain", "email": email, "txt_records": txt_records},
                        )
        except Exception as exc:
            logger.debug("Domain analysis failed for %s: %s", email, exc)
        return None

    async def _check_disposable(self, email: str) -> Finding | None:
        """Check if email is from a disposable email provider."""
        try:
            domain = email.split("@")[1]
            disposable_domains = {
                "tempmail.com", "throwaway.email", "guerrillamail.com",
                "mailinator.com", "yopmail.com", "10minutemail.com",
            }
            if domain.lower() in disposable_domains:
                return Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Disposable Email Detected: {email}",
                    description=f"Email is from disposable provider: {domain}",
                    severity=Severity.MEDIUM,
                    raw_data={"type": "disposable", "email": email, "domain": domain},
                )
        except Exception as exc:
            logger.debug("Disposable check failed for %s: %s", email, exc)
        return None
