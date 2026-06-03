"""LinkedIn Intelligence Module using CloakBrowser."""
import logging
from typing import Any, Optional
from pydantic import BaseModel, Field

from src.core.cloak_client import CloakScraper

logger = logging.getLogger(__name__)

class LinkedInProfile(BaseModel):
    url: str
    name: str = ""
    headline: str = ""
    location: str = ""
    about: str = ""
    experience: list[dict] = Field(default_factory=list)
    education: list[dict] = Field(default_factory=list)

class LinkedInIntel:
    """Scrapes LinkedIn profiles utilizing anti-detect CloakBrowser."""
    
    def __init__(self, force_cloak: bool = False):
        self.scraper = CloakScraper(force_cloak=force_cloak)
        
    async def get_profile(self, url: str) -> Optional[LinkedInProfile]:
        """Extract profile information from a LinkedIn URL."""
        if not url.startswith("https://www.linkedin.com/in/"):
            return None
            
        try:
            async with self.scraper.get_page() as page:
                await page.goto(url, timeout=30000, wait_until="domcontentloaded")
                
                # Check for auth wall / login redirect
                current_url = page.url
                if "authwall" in current_url or "login" in current_url:
                    logger.warning("LinkedIn threw auth wall for %s", url)
                    return None
                    
                # Extract basic info
                name_el = await page.query_selector("h1.text-heading-xlarge")
                name = await name_el.inner_text() if name_el else ""
                
                headline_el = await page.query_selector("div.text-body-medium")
                headline = await headline_el.inner_text() if headline_el else ""
                
                loc_el = await page.query_selector("span.text-body-small.inline.t-black--light.break-words")
                location = await loc_el.inner_text() if loc_el else ""
                
                about_el = await page.query_selector("div#about ~ div.display-flex span[aria-hidden='true']")
                about = await about_el.inner_text() if about_el else ""
                
                profile = LinkedInProfile(
                    url=url,
                    name=name.strip(),
                    headline=headline.strip(),
                    location=location.strip(),
                    about=about.strip()
                )
                
                # For experience and education we'd need more complex selectors, 
                # skipping for fast MVP but structure is in place.
                
                return profile
                
        except Exception as e:
            logger.debug("Failed to scrape LinkedIn profile %s: %s", url, e)
            return None
