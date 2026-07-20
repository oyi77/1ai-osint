"""CloakBrowser anti-detect scraping client — CDP only, no plain Playwright fallback."""

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from playwright.async_api import Page, async_playwright

logger = logging.getLogger(__name__)


class CloakScraper:
    """Manages anti-detect browser instances via CloakBrowser CDP."""

    def __init__(self, *, cloak_ws: str = "", cloak_api: str = ""):
        self.cloak_ws = cloak_ws or os.environ.get("CLOAKBROWSER_CDP_WS", "")
        self.cloak_api = cloak_api or os.environ.get(
            "CLOAKBROWSER_API_URL", ""
        )

    async def _get_cloak_websocket(self) -> str:
        """Resolve CloakBrowser CDP WebSocket URL from env or local API."""
        if self.cloak_ws:
            return self.cloak_ws
        if self.cloak_api:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"{self.cloak_api}/api/v1/active-profile"
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        ws_url = (
                            data.get("websocket_url")
                            or data.get("ws_endpoint")
                        )
                        if ws_url:
                            return ws_url
            except Exception as e:
                logger.debug(
                    "Failed to query CloakBrowser API at %s: %s",
                    self.cloak_api,
                    e,
                )
        return ""

    @asynccontextmanager
    async def get_page(self) -> AsyncGenerator[Page, None]:
        """Context manager yielding a Playwright page via CloakBrowser CDP."""
        ws_url = await self._get_cloak_websocket()
        if not ws_url:
            raise RuntimeError(
                "CloakBrowser CDP endpoint not configured — "
                "set CLOAKBROWSER_CDP_WS or CLOAKBROWSER_API_URL"
            )

        async with async_playwright() as p:
            logger.info("Connecting to CloakBrowser via CDP: %s", ws_url)
            browser = await p.chromium.connect_over_cdp(ws_url)
            context = browser.contexts[0] if browser.contexts else browser
            page = await context.new_page()
            try:
                yield page
            finally:
                await page.close()
