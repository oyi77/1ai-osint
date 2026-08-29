"""Hudson Rock infostealer breach source (free API, no key).

Queries Hudson Rock's free OSINT endpoints for machines compromised by
infostealer malware, correlated by email, username, domain, or IP. The data
reveals compromised credentials, associated domains, and malware families —
valuable cross-correlation with phone/email/identity intel.

Endpoints: https://cavalier.hudsonrock.com/api/json/v2/osint-tools/
  search-by-email / search-by-username / search-by-domain / search-by-ip
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


class HudsonRockIntel:
    """Infostealer breach intelligence from Hudson Rock (free API)."""

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    async def search(self, kind: str, value: str) -> dict[str, Any] | None:
        """Search by kind: email | username | domain | ip."""
        endpoint = {
            "email": f"{_BASE}/search-by-email?email={value}",
            "username": f"{_BASE}/search-by-username?username={value}",
            "domain": f"{_BASE}/search-by-domain?domain={value}",
            "ip": f"{_BASE}/search-by-ip?ip={value}",
        }.get(kind)
        if not endpoint:
            logger.debug("unknown hudson rock kind: %s", kind)
            return None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint)
                resp.raise_for_status()
                data = resp.json()
            # The API returns {"stealers": [...]} or similar; keep raw.
            return data
        except httpx.HTTPError as e:
            logger.debug("hudson rock %s(%s) failed: %s", kind, value, e)
            return None
