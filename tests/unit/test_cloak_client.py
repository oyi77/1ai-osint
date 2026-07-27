from unittest.mock import AsyncMock, patch

import pytest

from src.core.cloak_client import CloakScraper


@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv(
        "CLOAKBROWSER_CDP_WS", "ws://127.0.0.1:9222/devtools/browser/xyz"
    )


@pytest.mark.asyncio
async def test_cloak_scraper_cdp_ws(mock_env):
    scraper = CloakScraper()
    assert scraper.cloak_ws == "ws://127.0.0.1:9222/devtools/browser/xyz"


@pytest.mark.asyncio
async def test_cloak_scraper_get_page_cdp(mock_env):
    scraper = CloakScraper()

    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_page = AsyncMock()

    mock_browser.contexts = [mock_context]
    mock_context.new_page.return_value = mock_page

    with patch("src.core.cloak_client.async_playwright") as mock_playwright:
        mock_pw_context = AsyncMock()
        mock_pw_context.chromium.connect_over_cdp.return_value = mock_browser
        mock_playwright.return_value.__aenter__.return_value = mock_pw_context

        async with scraper.get_page() as page:
            assert page is mock_page

        mock_pw_context.chromium.connect_over_cdp.assert_called_once_with(
            "ws://127.0.0.1:9222/devtools/browser/xyz"
        )
        mock_page.close.assert_called_once()
        # Should not close browser when connected over CDP
        mock_browser.close.assert_not_called()


@pytest.mark.asyncio
async def test_cloak_scraper_local_fallback(monkeypatch):
    """When CloakBrowser CDP is unavailable, falls back to local Playwright."""
    monkeypatch.delenv("CLOAKBROWSER_CDP_WS", raising=False)
    monkeypatch.delenv("CLOAKBROWSER_API_URL", raising=False)

    scraper = CloakScraper()

    mock_browser = AsyncMock()
    mock_browser.is_connected.return_value = False
    mock_context = AsyncMock()
    mock_page = AsyncMock()
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    # _ensure_local_browser calls: await async_playwright().start()
    # which returns a Playwright object with .chromium
    mock_pw_instance = AsyncMock()
    mock_pw_instance.chromium.launch.return_value = mock_browser

    with patch("src.core.cloak_client.async_playwright") as mock_playwright:
        # async_playwright() returns an instance; .start() returns the pw object
        mock_playwright.return_value.start = AsyncMock(return_value=mock_pw_instance)

        async with scraper.get_page() as page:
            assert page is mock_page

        mock_pw_instance.chromium.launch.assert_called_once()
        mock_page.close.assert_called_once()
        mock_context.close.assert_called_once()
