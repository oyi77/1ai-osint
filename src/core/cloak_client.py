"""CloakBrowser anti-detect scraping client."""

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from playwright.async_api import Page, async_playwright

logger = logging.getLogger(__name__)


class CloakScraper:
    """Manages anti-detect browser instances utilizing CloakBrowser or standard Playwright."""

    def __init__(self, force_cloak: bool = False):
        self.cloak_ws = os.environ.get("CLOAKBROWSER_CDP_WS", "")
        self.cloak_api = os.environ.get("CLOAKBROWSER_API_URL", "")
        self.force_cloak = force_cloak or (os.environ.get("FORCE_CLOAKBROWSER") == "1")

    async def _get_cloak_websocket(self) -> str:
        """Query CloakBrowser local API for active debugging WebSocket URL."""
        if self.cloak_ws:
            return self.cloak_ws
        if self.cloak_api:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"{self.cloak_api}/api/v1/active-profile")
                    if resp.status_code == 200:
                        data = resp.json()
                        ws_url = data.get("websocket_url") or data.get("ws_endpoint")
                        if ws_url:
                            return ws_url
            except Exception as e:
                logger.debug(
                    "Failed to query CloakBrowser API at %s: %s", self.cloak_api, e
                )
        return ""

    @asynccontextmanager
    async def get_page(self) -> AsyncGenerator[Page, None]:
        """Context manager yielding a ready Playwright page. Uses CDP if CloakBrowser is available."""
        async with async_playwright() as p:
            ws_url = await self._get_cloak_websocket()

            if self.force_cloak and not ws_url:
                raise RuntimeError(
                    "CloakBrowser is forced but no CDP WebSocket URL could be resolved."
                )

            browser = None
            page = None
            try:
                if ws_url:
                    logger.info(
                        "Connecting to CloakBrowser via CDP endpoint: %s", ws_url
                    )
                    browser = await p.chromium.connect_over_cdp(ws_url)
                    context = browser.contexts[0] if browser.contexts else browser
                    page = await context.new_page()
                else:
                    logger.debug(
                        "CloakBrowser not configured — falling back to standard Playwright Chromium"
                    )
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()
                    await page.set_viewport_size({"width": 1280, "height": 800})

                yield page
            finally:
                if page:
                    await page.close()
                if browser and not ws_url:
                    # Do not terminate CloakBrowser daemon, only terminate locally spawned browser
                    await browser.close()
