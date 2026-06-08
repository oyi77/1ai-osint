import logging
from typing import Any

from src.core.cloak_client import CloakScraper

logger = logging.getLogger(__name__)


class DeepScraperEngine:
    """Active Web Scraper with anti-detection capabilities."""

    def __init__(self):
        self.scraper = CloakScraper()

    async def scrape_profile(self, url: str) -> dict[str, Any]:
        """Scrape webpage content using CloakBrowser CDP."""
        try:
            async with self.scraper.get_page() as page:
                await page.goto(url, timeout=20000, wait_until="domcontentloaded")
                title = await page.title()

                texts = await page.locator("p, span, div").all_inner_texts()
                text_content = " ".join([t.strip() for t in texts if t.strip()])
                text_content = text_content[:1200]

                images = await page.locator("img").all()
                pfp_url = ""
                for img in images:
                    src = await img.get_attribute("src")
                    if src:
                        src_lower = src.lower()
                        if any(
                            k in src_lower
                            for k in ("profile", "avatar", "pfp", "thumbnail")
                        ):
                            pfp_url = src
                            break

                return {
                    "url": url,
                    "title": title,
                    "text_content": text_content,
                    "profile_picture_url": pfp_url,
                }
        except Exception as e:
            logger.debug("Scraper failed to load %s: %s", url, e)
            return {}
