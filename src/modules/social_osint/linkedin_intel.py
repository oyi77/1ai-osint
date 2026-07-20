"""LinkedIn Intelligence Module using CloakBrowser."""

from __future__ import annotations

import logging
from typing import Optional

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


class LinkedInProfileResult(BaseModel):
    """Return type that communicates both success and failure reasons."""

    profile: Optional[LinkedInProfile] = None
    blocked: bool = False
    reason: str = ""
    """Short description of why the profile could not be fetched, e.g.
    'authwall', 'rate_limited', 'not_found', 'timeout', or empty on success."""


class LinkedInIntel:
    """Scrapes LinkedIn profiles utilizing anti-detect CloakBrowser.

    The get_profile() method returns a LinkedInProfileResult instead of None
    on failure, so callers can distinguish between:
    - Authwall (HTTP 999 / redirect to login page)
    - Rate limiting
    - Invalid URL
    - Generic scrape failure
    """

    def __init__(self):
        self.scraper = CloakScraper()

    async def get_profile(self, url: str) -> LinkedInProfileResult:
        """Extract profile information from a LinkedIn URL.

        Returns a LinkedInProfileResult with:
        - profile set to the LinkedInProfile on success
        - blocked=True and a human-readable reason on failure
        """
        if not url.startswith("https://www.linkedin.com/in/"):
            return LinkedInProfileResult(
                blocked=True,
                reason=f"Invalid LinkedIn URL: {url}",
            )

        try:
            async with self.scraper.get_page() as page:
                await page.goto(url, timeout=30000, wait_until="domcontentloaded")

                # Detect auth wall / login redirect
                current_url = page.url
                if "authwall" in current_url:
                    logger.warning("LinkedIn authwall for %s", url)
                    return LinkedInProfileResult(
                        blocked=True,
                        reason=(
                            "LinkedIn authwall (HTTP 999 rate limit) — "
                            "use a residential proxy or a logged-in browser session"
                        ),
                    )

                if "login" in current_url:
                    logger.warning("LinkedIn login redirect for %s", url)
                    return LinkedInProfileResult(
                        blocked=True,
                        reason=(
                            "LinkedIn login wall — profile requires authentication"
                        ),
                    )

                if "/notfound/" in current_url or "/pub/dir/" in current_url:
                    return LinkedInProfileResult(
                        blocked=False,
                        reason="LinkedIn profile not found or inaccessible",
                    )

                # Extract basic info
                name_el = await page.query_selector("h1.text-heading-xlarge")
                name = await name_el.inner_text() if name_el else ""

                headline_el = await page.query_selector("div.text-body-medium")
                headline = await headline_el.inner_text() if headline_el else ""

                loc_el = await page.query_selector(
                    "span.text-body-small.inline.t-black--light.break-words"
                )
                location = await loc_el.inner_text() if loc_el else ""

                about_el = await page.query_selector(
                    "div#about ~ div.display-flex span[aria-hidden='true']"
                )
                about = await about_el.inner_text() if about_el else ""

                profile = LinkedInProfile(
                    url=url,
                    name=name.strip(),
                    headline=headline.strip(),
                    location=location.strip(),
                    about=about.strip(),
                )

                # For experience and education we'd need more complex selectors,
                # skipping for fast MVP but structure is in place.

                return LinkedInProfileResult(profile=profile)

        except Exception as e:
            exc_reason = str(e) or type(e).__name__
            logger.debug("Failed to scrape LinkedIn profile %s: %s", url, exc_reason)
            return LinkedInProfileResult(
                blocked=True,
                reason=f"LinkedIn scrape failed: {exc_reason}",
            )
