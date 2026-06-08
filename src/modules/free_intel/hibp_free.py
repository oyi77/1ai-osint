"""Have I Been Pwned — free breach lookup."""

import logging
import os

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class BreachRecord(BaseModel):
    name: str = ""
    domain: str = ""
    breach_date: str = ""
    data_classes: list[str] = Field(
        default_factory=list
    )  # e.g. ["Emails", "Passwords", "Phone numbers"]
    description: str = ""
    is_verified: bool = False
    pwn_count: int = 0


class HIBPIntel:
    """Check emails against Have I Been Pwned.

    Requires HIBP_API_KEY env var for the v3 API.
    Without a key, uses the free breach name endpoint.
    """

    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self):
        self.api_key = os.environ.get("HIBP_API_KEY", "")

    async def check_email(self, email: str) -> list[BreachRecord]:
        """Check if an email appears in known breaches."""
        if not self.api_key:
            logger.info("HIBP_API_KEY not set — using limited breach check")
            return await self._check_free(email)

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE}/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": self.api_key,
                        "user-agent": "1ai-osint",
                    },
                    params={"truncateResponse": "false"},
                )
                if resp.status_code == 200:
                    return [
                        BreachRecord(
                            name=b.get("Name", ""),
                            domain=b.get("Domain", ""),
                            breach_date=b.get("BreachDate", ""),
                            data_classes=b.get("DataClasses", []),
                            description=b.get("Description", ""),
                            is_verified=b.get("IsVerified", False),
                            pwn_count=b.get("PwnCount", 0),
                        )
                        for b in resp.json()
                    ]
                elif resp.status_code == 404:
                    return []  # Not breached
        except Exception as e:
            logger.warning("HIBP check failed for %s: %s", email, e)
        return []

    async def _check_free(self, email: str) -> list[BreachRecord]:
        """Fallback: check breach status without API key (limited info)."""
        # Without API key, we can still check the breaches endpoint for general info
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE}/breaches",
                    headers={"user-agent": "1ai-osint"},
                )
                if resp.status_code == 200:
                    # Return known breaches list (not personalized, but useful context)
                    all_breaches = resp.json()
                    # Filter for major Indonesian-relevant breaches
                    relevant = [
                        b
                        for b in all_breaches
                        if any(
                            kw in b.get("Name", "").lower()
                            for kw in [
                                "tokopedia",
                                "bukalapak",
                                "bhinneka",
                                "indonesia",
                            ]
                        )
                    ]
                    return [
                        BreachRecord(
                            name=b.get("Name", ""),
                            domain=b.get("Domain", ""),
                            breach_date=b.get("BreachDate", ""),
                            data_classes=b.get("DataClasses", []),
                            is_verified=b.get("IsVerified", False),
                            pwn_count=b.get("PwnCount", 0),
                        )
                        for b in relevant[:10]
                    ]
        except Exception as e:
            logger.debug("HIBP free check failed: %s", e)
        return []
