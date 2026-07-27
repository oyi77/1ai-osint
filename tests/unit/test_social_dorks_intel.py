"""Tests for Social Media Dorks Intelligence module."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.modules.free_intel.social_dorks_intel import SocialDorksIntel


@pytest.mark.asyncio
async def test_social_dorks_search_success():
    intel = SocialDorksIntel()
    name = "John Doe"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # Include all targeted matching URLs and ignored edge cases to hit all code branches
    mock_resp.text = """
    <a href="https://www.instagram.com/johndoe_ig/?hl=en">Instagram</a>
    <a href="https://www.instagram.com/explore/tags">Explore Instagram (Ignore)</a>
    <a href="https://www.tiktok.com/@johndoe_tt">TikTok</a>
    <a href="https://www.facebook.com/johndoe_fb">Facebook</a>
    <a href="https://www.facebook.com/public/johndoe">Public FB Profile (Ignore)</a>
    <a href="https://twitter.com/johndoe_tw">Twitter</a>
    <a href="https://twitter.com/search?q=test">Twitter Search (Ignore)</a>
    <a href="https://x.com/johndoe_x">X</a>
    <a href="https://duckduckgo.com/?q=query">Ignore DuckDuckGo URL</a>
    <a href="https://www.instagram.com/login">Ignore Username login</a>
    """

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        results = await intel.search(name)

        assert len(results) >= 4
        platforms = {r.platform: r.username for r in results}
        assert "instagram" in platforms
        assert platforms["instagram"] == "johndoe_ig"
        assert "tiktok" in platforms
        assert platforms["tiktok"] == "johndoe_tt"
        assert "facebook" in platforms
        assert platforms["facebook"] == "johndoe_fb"
        assert "twitter" in platforms
        assert platforms["twitter"] in ["johndoe_tw", "johndoe_x"]


@pytest.mark.asyncio
async def test_social_dorks_search_exception():
    intel = SocialDorksIntel()
    name = "John Doe"

    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.ConnectError("Connection failed")

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        results = await intel.search(name)
        assert len(results) == 0
