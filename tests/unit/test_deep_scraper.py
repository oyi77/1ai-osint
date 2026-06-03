import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.modules.deep_scan.deep_scraper import DeepScraperEngine


@pytest.mark.asyncio
async def test_scrape_profile_success():
    engine = DeepScraperEngine()

    mock_page = AsyncMock()
    mock_page.title.return_value = "Test Title"

    mock_text_locator = AsyncMock()
    mock_text_locator.all_inner_texts.return_value = [
        "Hello",
        "World",
        "This is a test bio.",
    ]

    mock_img_locator = AsyncMock()
    mock_img = AsyncMock()
    mock_img.get_attribute.return_value = "https://example.com/avatar.png"
    mock_img_locator.all.return_value = [mock_img]

    def locator_side_effect(selector):
        if selector == "p, span, div":
            return mock_text_locator
        elif selector == "img":
            return mock_img_locator
        return AsyncMock()

    mock_page.locator = MagicMock(side_effect=locator_side_effect)

    class MockCloakScraperCM:
        async def __aenter__(self):
            return mock_page

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch(
        "src.modules.deep_scan.deep_scraper.CloakScraper.get_page",
        return_value=MockCloakScraperCM(),
    ):
        result = await engine.scrape_profile("https://example.com")

        assert result["url"] == "https://example.com"
        assert result["title"] == "Test Title"
        assert "Hello World This is a test bio." in result["text_content"]
        assert result["profile_picture_url"] == "https://example.com/avatar.png"


@pytest.mark.asyncio
async def test_scrape_profile_timeout():
    engine = DeepScraperEngine()

    mock_page = AsyncMock()
    mock_page.goto.side_effect = Exception("Timeout")

    class MockCloakScraperCM:
        async def __aenter__(self):
            return mock_page

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch(
        "src.modules.deep_scan.deep_scraper.CloakScraper.get_page",
        return_value=MockCloakScraperCM(),
    ):
        result = await engine.scrape_profile("https://example.com")

        assert result == {}
