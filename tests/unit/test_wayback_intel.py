from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.free_intel.wayback_intel import WaybackIntel


@pytest.mark.asyncio
async def test_find_snapshots_success():
    intel = WaybackIntel()
    mock_rows = [
        ["timestamp", "original"],
        ["20200101120000", "https://example.com"],
        ["20200201120000", "https://example.com"],
    ]
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = mock_rows
        client.get = AsyncMock(return_value=resp)

        results = await intel.find_snapshots("https://example.com")

        assert len(results) == 2
        assert results[0].timestamp == "20200101120000"
        assert results[0].archive_url == "https://web.archive.org/web/20200101120000/https://example.com"


@pytest.mark.asyncio
async def test_find_snapshots_failure():
    intel = WaybackIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        client.get = AsyncMock(side_effect=Exception("Connection error"))

        results = await intel.find_snapshots("https://example.com")
        assert results == []


@pytest.mark.asyncio
async def test_get_earliest_snapshot_success():
    intel = WaybackIntel()
    mock_data = {
        "archived_snapshots": {
            "closest": {
                "available": True,
                "url": "https://web.archive.org/web/20100101120000/https://example.com",
                "timestamp": "20100101120000",
            }
        }
    }
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = mock_data
        client.get = AsyncMock(return_value=resp)

        result = await intel.get_earliest_snapshot("https://example.com")
        assert result is not None
        assert result.timestamp == "20100101120000"
        assert result.url == "https://web.archive.org/web/20100101120000/https://example.com"


@pytest.mark.asyncio
async def test_get_earliest_snapshot_not_available():
    intel = WaybackIntel()
    mock_data = {"archived_snapshots": {}}
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = mock_data
        client.get = AsyncMock(return_value=resp)

        result = await intel.get_earliest_snapshot("https://example.com")
        assert result is None


@pytest.mark.asyncio
async def test_get_earliest_snapshot_exception():
    intel = WaybackIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        client.get = AsyncMock(side_effect=Exception("API Error"))

        result = await intel.get_earliest_snapshot("https://example.com")
        assert result is None
