"""People Finder module: Social media username search (Sherlock/Maigret/WhatsMyName)."""

import shutil
from typing import Any, Optional

from src.core.models import ScanResult
from src.modules.base.base import BaseOSINTTool
from src.modules.people_finder.search import PeopleFinderSearch

__all__ = ["PeopleFinderTool", "PeopleFinderSearch"]


class PeopleFinderTool(BaseOSINTTool):
    """Search for user profiles across social media platforms."""

    name = "people_finder"
    description = (
        "Search for usernames across social media platforms using Sherlock/Maigret"
    )
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
        self._search = PeopleFinderSearch(zkit_salt=zkit_salt)

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Search for username across social platforms."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan via PeopleFinderSearch (Sherlock + optional providers)."""
        return await self._search.scan(target, **kwargs)

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
