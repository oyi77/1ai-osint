"""People finder search module wrapping Sherlock, Maigret, and WhatsMyName."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool


class Profile(BaseModel):
    """A deduplicated social media profile."""

    platform: str = Field(..., description="Platform/site name")
    username: str = Field(..., description="Username on the platform")
    url: Optional[str] = Field(default=None, description="Profile URL")
    status: str = Field(default="found", description="found, possibly, error")
    source_providers: list[str] = Field(
        default_factory=list, description="Providers that found this profile"
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Confidence score"
    )
    raw_data: dict[str, Any] = Field(default_factory=dict)


# Minimum confidence threshold for including a profile
_CONFIDENCE_THRESHOLD = 0.3


class PeopleFinderSearch(BaseOSINTTool):
    """
    Search for user profiles across social media platforms.

    Wraps chiasmodon's Sherlock, Maigret, and WhatsMyName providers
    to perform parallel username searches with profile deduplication
    and confidence scoring.
    """

    name = "people_finder"
    description = "Social media username search across multiple providers"
    version = "0.1.0"

    def __init__(
        self,
        zkit_salt: Optional[str] = None,
        providers: Optional[list[str]] = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self._requested_providers = providers

    def _get_providers(self) -> dict[str, Any]:
        """Get available social media search providers."""
        available = {}
        try:
            from src.vendor.chiasmodon.providers.sherlock import SherlockProvider

            available["sherlock"] = SherlockProvider()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.providers.maigret import MaigretProvider

            available["maigret"] = MaigretProvider()
        except ImportError:
            pass
        try:
            from src.vendor.chiasmodon.providers.whatsmyname import (
                WhatsMyNameProvider,
            )

            available["whatsmyname"] = WhatsMyNameProvider()
        except ImportError:
            pass

        if self._requested_providers:
            return {
                k: v for k, v in available.items() if k in self._requested_providers
            }
        return available

    async def search(self, query: str, **kwargs) -> ScanResult:
        """
        Search for a username across social media platforms.

        Runs Sherlock, Maigret, and WhatsMyName in parallel,
        deduplicates results, and scores confidence.

        Args:
            query: Username to search for
        """
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        providers = self._get_providers()
        errors: dict[str, str] = {}

        # Run all providers concurrently
        tasks = []
        provider_names = list(providers.keys())
        for name, provider in providers.items():
            tasks.append(self._query_provider(name, provider, query))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect raw profiles from each provider
        raw_profiles: list[dict[str, Any]] = []
        for provider_name, result in zip(provider_names, results):
            if isinstance(result, Exception):
                errors[provider_name] = str(result)
                continue
            if isinstance(result, dict) and result.get("error"):
                errors[provider_name] = result["error"]
                continue
            parsed = self._parse_provider_results(provider_name, result)
            raw_profiles.extend(parsed)

        # Deduplicate profiles across providers
        profiles = self._deduplicate_profiles(raw_profiles)

        # Score confidence for each profile
        total_providers = len(providers) - len(errors)
        for profile in profiles:
            profile.confidence = self._score_confidence(
                profile.source_providers, total_providers
            )

        # Filter low-confidence profiles
        profiles = [
            p for p in profiles if p.confidence >= _CONFIDENCE_THRESHOLD
        ]

        # Build findings from profiles
        findings = []
        for profile in profiles:
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Profile: {profile.platform}/{profile.username}",
                    description=f"Found on {profile.platform} via {', '.join(profile.source_providers)}",
                    severity=Severity.INFO,
                    raw_data=profile.model_dump(exclude_none=True),
                    confidence=profile.confidence,
                    tags=["profile", "social", profile.platform],
                )
            )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=query,
            status="ok" if not errors else "partial",
            findings=findings,
            metadata={
                "providers_queried": list(providers.keys()),
                "providers_errored": errors,
                "total_profiles": len(profiles),
                "username": query,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Alias for search."""
        return await self.search(target, **kwargs)

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze search results for patterns."""
        if isinstance(data, ScanResult):
            findings = data.findings
        else:
            return {"error": "Unsupported data type"}

        platforms: dict[str, int] = {}
        confidence_buckets = {"high": 0, "medium": 0, "low": 0}

        for f in findings:
            platform = f.raw_data.get("platform", "unknown")
            platforms[platform] = platforms.get(platform, 0) + 1

            if f.confidence >= 0.7:
                confidence_buckets["high"] += 1
            elif f.confidence >= 0.5:
                confidence_buckets["medium"] += 1
            else:
                confidence_buckets["low"] += 1

        return {
            "total_profiles": len(findings),
            "platform_breakdown": platforms,
            "confidence_breakdown": confidence_buckets,
            "has_high_confidence": confidence_buckets["high"] > 0,
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Learn from feedback (future: adjust confidence weights)."""
        pass

    async def _query_provider(
        self, name: str, provider: Any, query: str
    ) -> dict:
        """Query a single provider in thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, provider.search, query)

    def _parse_provider_results(
        self, provider_name: str, result: Any
    ) -> list[dict[str, Any]]:
        """
        Parse a provider's raw result into normalized profile dicts.

        Each provider returns different formats:
        - Sherlock: {"site": {"url": ..., "status": ..., ...}}
        - Maigret: {"site": {"url": ..., "status": ..., ...}}
        - WhatsMyName: [{"platform": ..., "url": ..., ...}]
        """
        profiles = []

        if isinstance(result, dict) and result.get("error"):
            return profiles

        # Sherlock/Maigret format: dict of site -> details
        if isinstance(result, dict) and not result.get("error"):
            for site_name, site_data in result.items():
                if not isinstance(site_data, dict):
                    continue
                status = site_data.get("status", "").lower()
                if status in ("claimed", "found", "available"):
                    profiles.append(
                        {
                            "platform": site_name,
                            "username": site_data.get("username", ""),
                            "url": site_data.get("url", ""),
                            "status": "found",
                            "source_provider": provider_name,
                            "raw_data": site_data,
                        }
                    )
                elif status in ("possibly", "likely"):
                    profiles.append(
                        {
                            "platform": site_name,
                            "username": site_data.get("username", ""),
                            "url": site_data.get("url", ""),
                            "status": "possibly",
                            "source_provider": provider_name,
                            "raw_data": site_data,
                        }
                    )

        # WhatsMyName format: list of result dicts
        if isinstance(result, list):
            for item in result:
                if not isinstance(item, dict):
                    continue
                status = item.get("status", "").lower()
                if status in ("claimed", "found", "active"):
                    profiles.append(
                        {
                            "platform": item.get("platform")
                            or item.get("site", "unknown"),
                            "username": item.get("username", ""),
                            "url": item.get("url", ""),
                            "status": "found",
                            "source_provider": provider_name,
                            "raw_data": item,
                        }
                    )

        return profiles

    def _deduplicate_profiles(
        self, raw_profiles: list[dict[str, Any]]
    ) -> list[Profile]:
        """
        Deduplicate profiles across providers by platform key.

        When multiple providers find the same profile, merge them
        and track which providers contributed.
        """
        seen: dict[str, dict] = {}

        for p in raw_profiles:
            # Normalize platform name for dedup key
            platform_key = p["platform"].lower().strip()
            url = p.get("url", "")
            dedup_key = f"{platform_key}:{url}" if url else platform_key

            if dedup_key in seen:
                existing = seen[dedup_key]
                src = p["source_provider"]
                if src not in existing["source_providers"]:
                    existing["source_providers"].append(src)
                # Prefer "found" over "possibly"
                if p["status"] == "found" and existing["status"] != "found":
                    existing["status"] = "found"
            else:
                seen[dedup_key] = {
                    "platform": p["platform"],
                    "username": p.get("username", ""),
                    "url": p.get("url", ""),
                    "status": p.get("status", "found"),
                    "source_providers": [p["source_provider"]],
                    "raw_data": p.get("raw_data", {}),
                }

        profiles = []
        for data in seen.values():
            profiles.append(
                Profile(
                    platform=data["platform"],
                    username=data["username"],
                    url=data.get("url"),
                    status=data["status"],
                    source_providers=data["source_providers"],
                    raw_data=data["raw_data"],
                )
            )

        return profiles

    @staticmethod
    def _score_confidence(
        source_providers: list[str], total_available: int
    ) -> float:
        """
        Score confidence based on how many providers found the profile.

        - 1 provider: 0.5 base
        - 2 providers: 0.75
        - 3+ providers: 0.9
        Bonus for status being "found" vs "possibly".
        """
        if total_available <= 0:
            return 0.3

        count = len(source_providers)
        ratio = count / total_available

        if count >= 3:
            base = 0.9
        elif count >= 2:
            base = 0.75
        else:
            base = 0.5

        return min(base + (ratio * 0.1), 1.0)
