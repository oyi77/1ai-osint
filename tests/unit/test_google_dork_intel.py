from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.free_intel.google_dork_intel import DorkResult, GoogleDorkIntel


@pytest.mark.asyncio
async def test_search_extracts_emails():
    intel = GoogleDorkIntel()
    mock_html = '<span class="result__snippet">Contact us at admin@example.com for info</span>'
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        resp = MagicMock(status_code=200, text=mock_html)
        client.post = AsyncMock(return_value=resp)
        mock_get_resp = MagicMock(
            status_code=200,
            text="<html><script>ignore</script><body>Extracted email admin@example.com from high value link</body></html>",
        )
        client.get = AsyncMock(return_value=mock_get_resp)
        result = await intel.search("Test Person")
    assert isinstance(result, DorkResult)
    assert "admin@example.com" in result.extracted_emails


@pytest.mark.asyncio
async def test_search_extracts_phones():
    intel = GoogleDorkIntel()
    mock_html = '<span class="result__snippet">Call +6281234567890 or 081234567890</span>'
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        resp = MagicMock(status_code=200, text=mock_html)
        client.post = AsyncMock(return_value=resp)
        result = await intel.search("Test Person")
    assert len(result.extracted_phones) > 0


@pytest.mark.asyncio
async def test_search_extracts_linkedin():
    intel = GoogleDorkIntel()
    mock_html = 'href="https://www.linkedin.com/in/testperson"'
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        resp = MagicMock(status_code=200, text=mock_html)
        client.post = AsyncMock(return_value=resp)
        result = await intel.search("Test Person")
    assert any("linkedin.com/in/testperson" in u for u in result.linkedin_urls)


@pytest.mark.asyncio
async def test_search_handles_failure():
    intel = GoogleDorkIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        client.post = AsyncMock(side_effect=Exception("Network error"))
        result = await intel.search("Test Person")
    assert isinstance(result, DorkResult)
    assert result.extracted_emails == []


@pytest.mark.asyncio
async def test_search_get_exception():
    intel = GoogleDorkIntel()
    mock_html = '<a href="https://example.com/test.pdf">PDF link</a>'
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

        resp = MagicMock(status_code=200, text=mock_html)
        client.post = AsyncMock(return_value=resp)
        client.get = AsyncMock(side_effect=Exception("Fetch link failed"))

        result = await intel.search("Test Person")

    assert isinstance(result, DorkResult)
    assert len(result.pdf_urls) > 0
