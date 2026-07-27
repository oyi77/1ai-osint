"""Tests for Tech Jobs Intelligence module."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.modules.free_intel.tech_jobs_intel import TechJobsIntel


@pytest.mark.asyncio
async def test_tech_jobs_search_success():
    intel = TechJobsIntel()
    name = "John Doe"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = """
    <a class="result__url" href="https://techinasia.com/profile/johndoe">techinasia</a>
    <div class="result__snippet">John Doe is a Senior Software Engineer at TechInAsia</a>
    """

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        results = await intel.search(name)

        assert len(results) > 0
        assert results[0].platform == "techinasia.com"
        assert results[0].url == "https://techinasia.com/profile/johndoe"
        assert len(results[0].snippets) > 0
        assert "Senior Software Engineer" in results[0].snippets[0]
        assert mock_client.post.call_count == 3


@pytest.mark.asyncio
async def test_tech_jobs_search_exception():
    intel = TechJobsIntel()
    name = "John Doe"

    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.ConnectError("Connection failed")

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        results = await intel.search(name)
        assert len(results) == 0
