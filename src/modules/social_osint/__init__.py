"""Social Media OSINT module for cross-platform intelligence."""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from src.modules.base.base import BaseOSINTTool
from src.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class SocialOSINTTool(BaseOSINTTool):
    """Cross-platform social media intelligence tool.

    Searches for usernames across platforms, analyzes profiles,
    and monitors for mentions and activity.
    """

    name = "social_osint"

    PLATFORMS = {
        "github": "https://api.github.com/users/{username}",
        "gitlab": "https://gitlab.com/api/v4/users?username={username}",
        "reddit": "https://www.reddit.com/user/{username}/about.json",
        "twitter": "https://nitter.net/{username}",
        "instagram": "https://www.instagram.com/{username}/",
        "linkedin": "https://www.linkedin.com/in/{username}",
    }

    def __init__(self, **kwargs: Any):
        self.timeout = kwargs.pop("timeout", 30)
        super().__init__(**kwargs)

    async def search(self, query: str, **kwargs: Any) -> ScanResult:
        """Search for social media presence."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Perform cross-platform social media OSINT."""
        from src.modules.deep_scan.name_pivots import primary_username_for_name

        query = target.strip()
        if " " in query:
            query = primary_username_for_name(query)

        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        try:
            results = await asyncio.gather(
                self._search_github(query),
                self._search_gitlab(query),
                self._search_reddit(query),
                self._check_username_availability(query, display_name=target.strip()),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Social OSINT task failed: %s", result)
                    continue
                if isinstance(result, Finding):
                    findings.append(result)

        except Exception as exc:
            logger.error("Social OSINT failed: %s", exc)

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            metadata={
                "username": query,
                "display_name": target.strip() if target.strip() != query else None,
                "platforms_checked": len(self.PLATFORMS),
                "tasks_completed": len([r for r in results if not isinstance(r, Exception)]),
                "tasks_failed": len([r for r in results if isinstance(r, Exception)]),
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: Any, **kwargs: Any) -> dict[str, Any]:
        """Analyze social media OSINT results."""
        if isinstance(data, ScanResult):
            return {
                "total_findings": data.finding_count,
                "platforms_found": data.metadata.get("platforms_found", 0),
                "username": data.metadata.get("username", ""),
            }
        return {}

    async def learn(self, feedback: Any, **kwargs: Any) -> None:
        """Learn from feedback (no-op for now)."""
        pass

    async def _search_github(self, username: str) -> Finding | None:
        """Search for GitHub user."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://api.github.com/users/{username}")
                if resp.status_code == 200:
                    data = resp.json()
                    return Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        title=f"GitHub Profile Found: {username}",
                        description=f"Public repos: {data.get('public_repos', 0)}, Followers: {data.get('followers', 0)}",
                        severity=Severity.INFO,
                        raw_data={"type": "github", "username": username, "profile": data},
                    )
        except Exception as exc:
            logger.debug("GitHub search failed for %s: %s", username, exc)
        return None

    async def _search_gitlab(self, username: str) -> Finding | None:
        """Search for GitLab user."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://gitlab.com/api/v4/users?username={username}")
                if resp.status_code == 200:
                    data = resp.json()
                    if data:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"GitLab Profile Found: {username}",
                            description=f"User ID: {data[0].get('id', 'unknown')}",
                            severity=Severity.INFO,
                            raw_data={"type": "gitlab", "username": username, "profile": data[0]},
                        )
        except Exception as exc:
            logger.debug("GitLab search failed for %s: %s", username, exc)
        return None

    async def _search_reddit(self, username: str) -> Finding | None:
        """Search for Reddit user."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://www.reddit.com/user/{username}/about.json",
                    headers={"User-Agent": "1ai-osint/0.1.0"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    if data:
                        return Finding(
                            id=self._make_finding_id(),
                            module=self.name,
                            title=f"Reddit Profile Found: {username}",
                            description=f"Karma: {data.get('link_karma', 0) + data.get('comment_karma', 0)}",
                            severity=Severity.INFO,
                            raw_data={"type": "reddit", "username": username, "profile": data},
                        )
        except Exception as exc:
            logger.debug("Reddit search failed for %s: %s", username, exc)
        return None

    async def _check_username_availability(
        self, username: str, *, display_name: str | None = None,
    ) -> Finding | None:
        """Check username availability across platforms."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                platforms_checked = []
                for platform, url_template in self.PLATFORMS.items():
                    try:
                        url = url_template.format(username=username)
                        resp = await client.get(url)
                        platforms_checked.append({
                            "platform": platform,
                            "status": resp.status_code,
                            "exists": resp.status_code == 200,
                        })
                    except Exception:
                        platforms_checked.append({
                            "platform": platform,
                            "status": "error",
                            "exists": False,
                        })

                found = [p for p in platforms_checked if p.get("exists")]
                if found:
                    return Finding(
                        id=self._make_finding_id(),
                        module=self.name,
                        title=f"Username Found: {username}",
                        description=f"Found on {len(found)} platforms",
                        severity=Severity.INFO,
                        raw_data={
                            "type": "username_check",
                            "username": username,
                            "display_name": display_name,
                            "platforms": platforms_checked,
                        },
                    )
        except Exception as exc:
            logger.debug("Username check failed for %s: %s", username, exc)
        return None
