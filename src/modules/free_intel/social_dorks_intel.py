"""Social Media Dorks — explicitly extracts social media handles from search engines.

Tries DuckDuckGo first (free, no API key). Falls back to Bing when DuckDuckGo
is blocked or returns no results. Reports when all search engines are blocked
instead of silently returning empty results.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SocialDorkResult(BaseModel):
    platform: str = ""
    username: str = ""
    url: str = ""
    snippet: str = ""


@dataclass
class SocialDorkSearchResult:
    """Return type for search() that includes blockage information.

    Supports list-like operations (__len__, __iter__, __getitem__) by delegating
    to self.results for backward compatibility.
    """

    results: list[SocialDorkResult] = field(default_factory=list)
    blocked_msg: str = ""
    """Non-empty when one or more search engines were blocked."""

    def __len__(self) -> int:
        return len(self.results)

    def __iter__(self):
        return iter(self.results)

    def __getitem__(self, index):
        return self.results[index]


class SocialDorksIntel:
    """Uses explicit dorks to find IG/FB/TikTok handles via search engines."""

    ENDPOINTS = [
        "https://html.duckduckgo.com/html/",
        "https://www.bing.com/search",
    ]

    _BLOCKED_MSG: str = ""
    """Set to a non-empty string when all search engines are blocked."""

    @staticmethod
    def _parse_social_results(text: str, platform: str, engine_label: str) -> list[SocialDorkResult]:
        """Extract social media handles from search result HTML."""
        results: list[SocialDorkResult] = []
        urls = re.findall(r'href="(https?://[^"]+)"', text)

        for url in urls:
            if "duckduckgo" in url or "lite" in url:
                continue

            username = ""
            if platform == "instagram" and "instagram.com/" in url:
                parts = url.split("instagram.com/")
                if len(parts) > 1 and "p/" not in parts[1] and "explore/" not in parts[1]:
                    username = parts[1].split("/")[0].split("?")[0]
            elif platform == "tiktok" and "tiktok.com/@" in url:
                parts = url.split("tiktok.com/@")
                if len(parts) > 1:
                    username = parts[1].split("/")[0].split("?")[0]
            elif platform == "facebook" and "facebook.com/" in url:
                parts = url.split("facebook.com/")
                if len(parts) > 1 and "public/" not in parts[1]:
                    username = parts[1].split("/")[0].split("?")[0]
            elif platform == "twitter" and ("twitter.com/" in url or "x.com/" in url):
                separator = "twitter.com/" if "twitter.com/" in url else "x.com/"
                parts = url.split(separator)
                if len(parts) > 1 and "search" not in parts[1]:
                    username = parts[1].split("/")[0].split("?")[0]

            if username and username not in [
                "login",
                "signup",
                "about",
            ]:
                results.append(SocialDorkResult(platform=platform, username=username, url=url))

        return results

    async def search(self, name: str) -> SocialDorkSearchResult:
        """Search for social media handles across platforms.

        Tries DuckDuckGo first, then falls back to Bing. Sets _BLOCKED_MSG
        when all search engines are blocked so callers can report the issue.
        """
        queries = [
            (f'"{name}" site:instagram.com', "instagram"),
            (f'"{name}" site:tiktok.com', "tiktok"),
            (f'"{name}" site:facebook.com', "facebook"),
            (f'"{name}" site:twitter.com OR site:x.com', "twitter"),
        ]

        results: list[SocialDorkResult] = []
        self._BLOCKED_MSG = ""
        blocked_reasons: list[str] = []

        async with httpx.AsyncClient(
            timeout=15.0,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            },
        ) as client:
            # Phase 1: DuckDuckGo
            ddg_ok = False
            for q, platform in queries:
                try:
                    resp = await client.post(self.ENDPOINTS[0], data={"q": q})
                    if resp.status_code == 200:
                        ddg_ok = True
                        parsed = self._parse_social_results(
                            text=resp.text,
                            platform=platform,
                            engine_label="duckduckgo",
                        )
                        results.extend(parsed)
                    elif resp.status_code in (429, 403):
                        blocked_reasons.append(f"DuckDuckGo returned HTTP {resp.status_code} for {platform}")
                    await asyncio.sleep(1.0)
                except Exception as e:
                    blocked_reasons.append(f"DuckDuckGo failed for {platform}: {e}")

            # Phase 2: Bing fallback when DDG produced nothing or failed
            if not ddg_ok or not results:
                if blocked_reasons:
                    logger.info(
                        "DuckDuckGo blocked (%s), trying Bing fallback",
                        "; ".join(blocked_reasons),
                    )
                else:
                    logger.info("DuckDuckGo returned no results, trying Bing fallback")

                for q, platform in queries:
                    try:
                        resp = await client.get(
                            self.ENDPOINTS[1],
                            params={"q": q, "mkt": "en-US"},
                            follow_redirects=True,
                        )
                        if resp.status_code == 200:
                            parsed = self._parse_social_results(
                                text=resp.text,
                                platform=platform,
                                engine_label="bing",
                            )
                            results.extend(parsed)
                        elif resp.status_code in (429, 403):
                            blocked_reasons.append(f"Bing returned HTTP {resp.status_code} for {platform}")
                        await asyncio.sleep(0.5)
                    except Exception as e:
                        blocked_reasons.append(f"Bing failed for {platform}: {e}")

        # Set blocked message when all search engines failed
        if blocked_reasons and not results:
            self._BLOCKED_MSG = "All search engines blocked: " + "; ".join(blocked_reasons)
        elif blocked_reasons and results:
            self._BLOCKED_MSG = "Partial search blockage: " + "; ".join(blocked_reasons)

        # Deduplicate
        unique = []
        seen = set()
        for r in results:
            if r.username and r.username not in seen:
                seen.add(r.username)
                unique.append(r)

        if not unique and self._BLOCKED_MSG:
            logger.warning("Social dork search: %s", self._BLOCKED_MSG)

        return SocialDorkSearchResult(
            results=unique,
            blocked_msg=self._BLOCKED_MSG,
        )
