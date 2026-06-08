"""GitHub Intelligence Extractor — extracts real PII from GitHub APIs.

Free tier: 60 requests/hour unauthenticated.
With GITHUB_TOKEN env var: 5000 requests/hour.
"""

import logging
import os

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GitHubProfile(BaseModel):
    username: str = ""
    full_name: str = ""
    email: str = ""
    company: str = ""
    location: str = ""
    bio: str = ""
    blog: str = ""
    twitter_username: str = ""
    avatar_url: str = ""
    public_repos: int = 0
    followers: int = 0
    following: int = 0
    created_at: str = ""
    commit_emails: list[str] = Field(default_factory=list)
    repo_names: list[str] = Field(default_factory=list)


class GitHubIntel:
    BASE = "https://api.github.com"

    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN", "")

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "User-Agent": "1ai-osint/0.1"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def extract(self, username: str) -> GitHubProfile:
        """Extract full intelligence from a GitHub username."""
        profile = GitHubProfile(username=username)
        async with httpx.AsyncClient(timeout=15.0, headers=self._headers()) as client:
            # 1. User profile
            try:
                resp = await client.get(f"{self.BASE}/users/{username}")
                if resp.status_code == 200:
                    data = resp.json()
                    profile.full_name = data.get("name") or ""
                    profile.email = data.get("email") or ""
                    profile.company = data.get("company") or ""
                    profile.location = data.get("location") or ""
                    profile.bio = data.get("bio") or ""
                    profile.blog = data.get("blog") or ""
                    profile.twitter_username = data.get("twitter_username") or ""
                    profile.avatar_url = data.get("avatar_url") or ""
                    profile.public_repos = data.get("public_repos", 0)
                    profile.followers = data.get("followers", 0)
                    profile.following = data.get("following", 0)
                    profile.created_at = data.get("created_at") or ""
            except Exception as e:
                logger.warning("GitHub profile fetch failed for %s: %s", username, e)

            # 2. Extract commit emails from public events
            try:
                resp = await client.get(f"{self.BASE}/users/{username}/events/public")
                if resp.status_code == 200:
                    events = resp.json()
                    emails = set()
                    for event in events:
                        if event.get("type") == "PushEvent":
                            for commit in event.get("payload", {}).get("commits", []):
                                author = commit.get("author", {})
                                email = author.get("email", "")
                                if email and "noreply" not in email and "@" in email:
                                    emails.add(email)
                    profile.commit_emails = sorted(emails)
            except Exception as e:
                logger.debug("GitHub events fetch failed for %s: %s", username, e)

            # 3. Get repo names (top 5 by stars)
            try:
                resp = await client.get(
                    f"{self.BASE}/users/{username}/repos",
                    params={"sort": "updated", "per_page": 5},
                )
                if resp.status_code == 200:
                    repos = resp.json()
                    profile.repo_names = [
                        r.get("name", "") for r in repos if isinstance(r, dict)
                    ]
            except Exception as e:
                logger.debug("GitHub repos fetch failed for %s: %s", username, e)

        return profile
