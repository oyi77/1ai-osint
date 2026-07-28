"""CloakBrowser anti-detect scraping client with local Playwright fallback.

Features:
- CloakBrowser CDP connection (primary)
- Local Playwright fallback (when CloakBrowser not available)
- Browser fingerprint spoofing (viewport, locale, timezone)
- Stealth evasion via JS injections (WebDriver, navigator, chrome runtime)
- Connection pool management (reuse browser contexts)
- Health check method
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from playwright.async_api import Browser, Page, async_playwright

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stealth evasion JS — injected into every page to hide automation traces
# ---------------------------------------------------------------------------

STEALTH_JS = """
// Override navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true,
});

// Override chrome.runtime to appear as a real browser
window.chrome = {
    runtime: {
        onMessage: { addListener: () => {} },
        onConnect: { addListener: () => {} },
        onInstalled: { addListener: () => {} },
    },
    loadTimes: () => {},
    csi: () => {},
    app: { isInstalled: false, InstallState: { DISABLED: 'disabled' } },
};

// Override navigator.plugins length (headless has 0)
Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5],
    configurable: true,
});

// Override navigator.languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
    configurable: true,
});

// Remove webdriver痕迹 from permissions
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters)
);

// Override console.debug which Playwright uses for CDP logs
const originalDebug = console.debug;
console.debug = () => {};
"""

# ---------------------------------------------------------------------------
# Default fingerprint overrides
# ---------------------------------------------------------------------------

DEFAULT_VIEWPORT = {"width": 1920, "height": 1080}
DEFAULT_LOCALE = "en-US"
DEFAULT_TIMEZONE = "America/New_York"


class CloakScraper:
    """Manages anti-detect browser instances with CloakBrowser CDP + local fallback.

    The scraper first attempts to connect to a CloakBrowser instance via CDP.
    If no CDP endpoint is configured, it falls back to a local Playwright
    browser with stealth evasion and fingerprint spoofing.
    """

    def __init__(
        self,
        *,
        cloak_ws: str = "",
        cloak_api: str = "",
        headless: bool = True,
        viewport: dict[str, int] | None = None,
        locale: str = "",
        timezone_id: str = "",
    ) -> None:
        """Args:
        cloak_ws: CloakBrowser CDP WebSocket URL. Falls back to
            ``CLOAKBROWSER_CDP_WS`` env var.
        cloak_api: CloakBrowser REST API URL. Falls back to
            ``CLOAKBROWSER_API_URL`` env var.
        headless: Run local browser in headless mode (default True).
            Ignored when connecting to CloakBrowser CDP.
        viewport: Custom viewport dict ``{width, height}``.
            Default ``{1920, 1080}``.
        locale: Browser locale (e.g. ``"en-US"``). Default ``"en-US"``.
        timezone_id: Browser timezone ID (e.g. ``"America/New_York"``).
            Default ``"America/New_York"``.

        """
        self.cloak_ws = cloak_ws or os.environ.get("CLOAKBROWSER_CDP_WS", "")
        self.cloak_api = cloak_api or os.environ.get("CLOAKBROWSER_API_URL", "")
        self.headless = headless
        self._viewport = viewport or DEFAULT_VIEWPORT
        self._locale = locale or DEFAULT_LOCALE
        self._timezone_id = timezone_id or DEFAULT_TIMEZONE

        # Pooled resources (local mode)
        self._playwright: Any | None = None
        self._browser: Browser | None = None

    # ------------------------------------------------------------------
    # CloakBrowser CDP resolution
    # ------------------------------------------------------------------

    async def _get_cloak_websocket(self) -> str:
        """Resolve CloakBrowser CDP WebSocket URL from env or local API.

        Returns:
            The WebSocket URL string, or empty string if unavailable.

        """
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
                    "Failed to query CloakBrowser API at %s: %s",
                    self.cloak_api,
                    e,
                )
        return ""

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> dict[str, Any]:
        """Check whether CloakBrowser or local Playwright is available.

        Returns:
            A dict with ``status`` (``"ok"`` or ``"unavailable"``),
            ``mode`` (``"cloak"``, ``"local"``, or ``"none"``),
            and optional ``error``.

        """
        # Check CloakBrowser CDP
        ws_url = await self._get_cloak_websocket()
        if ws_url:
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.connect_over_cdp(ws_url)
                    await browser.close()
                return {"status": "ok", "mode": "cloak"}
            except Exception as e:
                logger.debug("CloakBrowser health check failed: %s", e)

        # Check local Playwright
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                await browser.close()
            return {"status": "ok", "mode": "local"}
        except Exception as e:
            return {"status": "unavailable", "mode": "none", "error": str(e)}

    # ------------------------------------------------------------------
    # Fingerprint spoofing
    # ------------------------------------------------------------------

    async def _apply_stealth(self, page: Page) -> None:
        """Apply stealth evasion JS and fingerprint overrides to a page.

        Args:
            page: The Playwright Page to patch.

        """
        # Inject stealth JS
        await page.add_init_script(STEALTH_JS)

        # Override navigator.webdriver via CDP
        try:
            await page.context.add_init_script(
                """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                """
            )
        except Exception:
            pass

    def _get_context_args(self) -> dict[str, Any]:
        """Return launch/context arguments for fingerprint spoofing.

        Returns:
            A dict of keyword arguments for
            ``browser.new_context()`` or ``playwright.chromium.launch_persistent_context()``.

        """
        return {
            "viewport": self._viewport,
            "locale": self._locale,
            "timezone_id": self._timezone_id,
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "geolocation": None,
            "permissions": [],
        }

    # ------------------------------------------------------------------
    # Connection pool (local mode)
    # ------------------------------------------------------------------

    async def _ensure_local_browser(self) -> Browser:
        """Ensure a local Playwright browser instance is running.

        Returns:
            A connected Browser instance.

        """
        if self._browser and self._browser.is_connected():
            return self._browser

        # Clean up any stale resources
        await self._cleanup_local()

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ],
        )
        logger.info("Launched local Playwright browser (headless=%s)", self.headless)
        assert self._browser is not None
        return self._browser

    async def _cleanup_local(self) -> None:
        """Clean up local browser and playwright resources."""
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    # ------------------------------------------------------------------
    # Context manager: get_page
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def get_page(self) -> AsyncGenerator[Page, None]:
        """Context manager yielding a Playwright page.

        Attempts CloakBrowser CDP first. Falls back to a local Playwright
        browser with stealth evasion if CDP is unavailable.

        Yields:
            A Playwright ``Page`` ready for navigation.

        Raises:
            RuntimeError: If both CloakBrowser and local Playwright
                are unavailable.

        """
        ws_url = await self._get_cloak_websocket()

        if ws_url:
            # ---------- CloakBrowser CDP mode ----------
            async with async_playwright() as p:
                logger.info("Connecting to CloakBrowser via CDP: %s", ws_url)
                browser = await p.chromium.connect_over_cdp(ws_url)
                context = browser.contexts[0] if browser.contexts else await browser.new_context()
                page = await context.new_page()
                await self._apply_stealth(page)
                try:
                    yield page
                finally:
                    await page.close()
                    # Do NOT close browser when connected over CDP
        else:
            # ---------- Local Playwright fallback ----------
            logger.info("CloakBrowser CDP unavailable — using local Playwright fallback")
            browser = await self._ensure_local_browser()
            context = await browser.new_context(**self._get_context_args())
            page = await context.new_page()
            await self._apply_stealth(page)
            try:
                yield page
            finally:
                await page.close()
                await context.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release pooled local browser resources.

        Does nothing in CloakBrowser CDP mode since those connections
        are ephemeral (per-call).
        """
        await self._cleanup_local()
        logger.info("CloakScraper resources released")

    async def __aenter__(self) -> CloakScraper:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
