"""Tech Jobs Intelligence — searches Glints and TechInAsia for developer profiles."""

import logging
import re
import asyncio
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TechJobProfile(BaseModel):
    platform: str = ""
    url: str = ""
    snippets: list[str] = Field(default_factory=list)


class TechJobsIntel:
    """Searches Glints and TechInAsia using DuckDuckGo."""

    ENDPOINTS = ["https://html.duckduckgo.com/html/"]

    async def search(self, name: str) -> list[TechJobProfile]:
        """Search specifically on tech job platforms."""
        queries = [
            f'"{name}" site:techinasia.com',
            f'"{name}" site:glints.com/id/profile',
            f'"{name}" site:kalibrr.com',
        ]

        results = []
        async with httpx.AsyncClient(
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        ) as client:
            for q in queries:
                try:
                    resp = await client.post(self.ENDPOINTS[0], data={"q": q})
                    if resp.status_code == 200:
                        text = resp.text
                        urls = re.findall(r'href="(https?://[^"]+)"', text)
                        valid_urls = [
                            u
                            for u in urls
                            if any(
                                d in u
                                for d in ["techinasia.com", "glints.com", "kalibrr.com"]
                            )
                        ]

                        # Get snippets
                        snippets = re.findall(
                            r'class="result__snippet"[^>]*>(.*?)</a', text, re.DOTALL
                        )
                        clean_snippets = [
                            " ".join(re.sub(r"<[^>]+>", " ", s).strip().split())
                            for s in snippets
                        ]

                        if valid_urls or clean_snippets:
                            results.append(
                                TechJobProfile(
                                    platform=q.split("site:")[1],
                                    url=valid_urls[0] if valid_urls else "",
                                    snippets=clean_snippets,
                                )
                            )
                    await asyncio.sleep(1.0)
                except Exception as e:
                    logger.debug("TechJobs search failed: %s", e)

        return results
