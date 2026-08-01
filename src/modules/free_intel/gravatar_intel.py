"""Gravatar Intelligence — lookup profiles by email hash."""

import hashlib
import logging

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GravatarProfile(BaseModel):
    email_hash: str = ""
    display_name: str = ""
    profile_url: str = ""
    photo_url: str = ""
    about_me: str = ""
    current_location: str = ""
    verified_accounts: list[dict] = Field(default_factory=list)


class GravatarIntel:
    async def lookup(self, email: str) -> GravatarProfile | None:
        """Look up a Gravatar profile by email address."""
        email_hash = hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    entry = data.get("entry", [{}])[0]
                    return GravatarProfile(
                        email_hash=email_hash,
                        display_name=entry.get("displayName") or entry.get("preferredUsername") or "",
                        profile_url=entry.get("profileUrl") or "",
                        photo_url=entry.get("thumbnailUrl") or "",
                        about_me=entry.get("aboutMe") or "",
                        current_location=entry.get("currentLocation") or "",
                        verified_accounts=[
                            {
                                "domain": a.get("domain"),
                                "url": a.get("url"),
                                "username": a.get("username"),
                            }
                            for a in entry.get("accounts", [])
                        ],
                    )
        except Exception as e:
            logger.debug("Gravatar lookup failed for %s: %s", email, e)
        return None
