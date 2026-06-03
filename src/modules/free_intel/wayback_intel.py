"""Wayback Machine Intelligence — find historical profile data."""

import logging
from typing import Optional
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class WaybackSnapshot(BaseModel):
    url: str = ""
    timestamp: str = ""  # YYYYMMDDHHMMSS
    archive_url: str = ""


class WaybackIntel:
    """Query Wayback Machine for historical snapshots of profile URLs."""

    CDX_API = "https://web.archive.org/cdx/search/cdx"

    async def find_snapshots(self, url: str, limit: int = 5) -> list[WaybackSnapshot]:
        """Find archived snapshots of a URL."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    self.CDX_API,
                    params={
                        "url": url,
                        "output": "json",
                        "limit": limit,
                        "fl": "timestamp,original",
                        "filter": "statuscode:200",
                        "collapse": "timestamp:6",  # One per month
                    },
                )
                if resp.status_code == 200:
                    rows = resp.json()
                    if len(rows) > 1:  # First row is header
                        return [
                            WaybackSnapshot(
                                url=row[1],
                                timestamp=row[0],
                                archive_url=f"https://web.archive.org/web/{row[0]}/{row[1]}",
                            )
                            for row in rows[1:]
                        ]
        except Exception as e:
            logger.debug("Wayback lookup failed for %s: %s", url, e)
        return []

    async def get_earliest_snapshot(self, url: str) -> Optional[WaybackSnapshot]:
        """Get the earliest available snapshot."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    "https://archive.org/wayback/available",
                    params={"url": url, "timestamp": "19900101"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    snap = data.get("archived_snapshots", {}).get("closest", {})
                    if snap.get("available"):
                        return WaybackSnapshot(
                            url=snap.get("url", ""),
                            timestamp=snap.get("timestamp", ""),
                            archive_url=snap.get("url", ""),
                        )
        except Exception as e:
            logger.debug("Wayback earliest failed for %s: %s", url, e)
        return None
