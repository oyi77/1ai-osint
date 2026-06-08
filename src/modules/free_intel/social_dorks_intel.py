"""Social Media Dorks — explicitly extracts social media handles from DuckDuckGo."""

import asyncio
import logging
import re

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SocialDorkResult(BaseModel):
    platform: str = ""
    username: str = ""
    url: str = ""
    snippet: str = ""


class SocialDorksIntel:
    """Uses explicit dorks to find IG/FB/TikTok handles."""

    ENDPOINTS = ["https://html.duckduckgo.com/html/"]

    async def search(self, name: str) -> list[SocialDorkResult]:
        queries = [
            (f'"{name}" site:instagram.com', "instagram"),
            (f'"{name}" site:tiktok.com', "tiktok"),
            (f'"{name}" site:facebook.com', "facebook"),
            (f'"{name}" site:twitter.com OR site:x.com', "twitter"),
        ]

        results = []
        async with httpx.AsyncClient(
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        ) as client:
            for q, platform in queries:
                try:
                    resp = await client.post(self.ENDPOINTS[0], data={"q": q})
                    if resp.status_code == 200:
                        text = resp.text
                        urls = re.findall(r'href="(https?://[^"]+)"', text)

                        for url in urls:
                            if "duckduckgo" in url or "lite" in url:
                                continue

                            # Extract username from URL
                            username = ""
                            if platform == "instagram" and "instagram.com/" in url:
                                parts = url.split("instagram.com/")
                                if (
                                    len(parts) > 1
                                    and "p/" not in parts[1]
                                    and "explore/" not in parts[1]
                                ):
                                    username = parts[1].split("/")[0].split("?")[0]
                            elif platform == "tiktok" and "tiktok.com/@" in url:
                                parts = url.split("tiktok.com/@")
                                if len(parts) > 1:
                                    username = parts[1].split("/")[0].split("?")[0]
                            elif platform == "facebook" and "facebook.com/" in url:
                                parts = url.split("facebook.com/")
                                if len(parts) > 1 and "public/" not in parts[1]:
                                    username = parts[1].split("/")[0].split("?")[0]
                            elif platform == "twitter" and (
                                "twitter.com/" in url or "x.com/" in url
                            ):
                                separator = (
                                    "twitter.com/"
                                    if "twitter.com/" in url
                                    else "x.com/"
                                )
                                parts = url.split(separator)
                                if len(parts) > 1 and "search" not in parts[1]:
                                    username = parts[1].split("/")[0].split("?")[0]

                            if username and username not in [
                                "login",
                                "signup",
                                "about",
                            ]:
                                results.append(
                                    SocialDorkResult(
                                        platform=platform, username=username, url=url
                                    )
                                )
                    await asyncio.sleep(1.0)
                except Exception as e:
                    logger.debug("Social dork failed for %s: %s", platform, e)

        # Deduplicate
        unique = []
        seen = set()
        for r in results:
            if r.username and r.username not in seen:
                seen.add(r.username)
                unique.append(r)

        return unique
