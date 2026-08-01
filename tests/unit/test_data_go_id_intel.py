"""Regression tests for data.go.id intel adapter.

Covers the failure paths (network error, non-200) that used to log with an
invalid ``%q`` format string — which raised ``ValueError`` inside the except
handler — plus flight-data title extraction, chrome filtering, and limit.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.free_intel.data_go_id_intel import DataGoIdIntel


def _mock_async_client(get_impl: AsyncMock) -> MagicMock:
    """Build a mock ``httpx.AsyncClient`` whose ``get`` is ``get_impl``."""
    client = AsyncMock()
    client.get = get_impl
    mock_client = MagicMock()
    mock_client.__aenter__.return_value = client
    return mock_client


@pytest.mark.asyncio
async def test_search_fetch_error_returns_empty():
    """A transport-level error must return [] and must not raise (regression: %q logger bug)."""
    intel = DataGoIdIntel()
    mock_client = _mock_async_client(AsyncMock(side_effect=ConnectionError("boom")))

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await intel.search_datasets("pendidikan")

    assert result == []


@pytest.mark.asyncio
async def test_search_non_200_returns_empty():
    """A non-200 response returns [] without raising."""
    intel = DataGoIdIntel()
    resp = MagicMock(status_code=500)
    mock_client = _mock_async_client(AsyncMock(return_value=resp))

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await intel.search_datasets("pendidikan")

    assert result == []


@pytest.mark.asyncio
async def test_search_extracts_titles_and_filters_chrome():
    """Titles are extracted from flight data; org names and stopwords are dropped."""
    text = (
        # Two real-looking dataset titles.
        '\\"title\\":\\"Statistik Pendidikan Tinggi 2024\\",\\"type\\":\\"dataset\\",'
        '\\"title\\":\\"Dataset Populasi Penduduk Indonesia 2023\\"'
        # An organization object — must be filtered out via _ORG_TYPE_RE.
        ',\\"title\\":\\"Kementerian Pendidikan\\",\\"type\\":\\"organization\\"'
        # A UI-chrome string — must be filtered via stopwords.
        ',\\"title\\":\\"kategori\\"'
    )
    resp = MagicMock(status_code=200)
    resp.text = text
    mock_client = _mock_async_client(AsyncMock(return_value=resp))

    intel = DataGoIdIntel()
    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await intel.search_datasets("pendidikan")

    titles = [r["title"] for r in result]
    assert "Statistik Pendidikan Tinggi 2024" in titles
    assert "Dataset Populasi Penduduk Indonesia 2023" in titles
    assert "Kementerian Pendidikan" not in titles
    assert "kategori" not in titles


@pytest.mark.asyncio
async def test_search_respects_limit():
    """``limit`` caps the number of returned datasets."""
    text = (
        '\\"title\\":\\"Statistik Pendidikan Tinggi 2024\\"'
        ',\\"title\\":\\"Dataset Populasi Penduduk Indonesia 2023\\"'
        ',\\"title\\":\\"Data Kependudukan Kota Besar Indonesia\\"'
    )
    resp = MagicMock(status_code=200)
    resp.text = text
    mock_client = _mock_async_client(AsyncMock(return_value=resp))

    intel = DataGoIdIntel()
    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await intel.search_datasets("pendidikan", limit=1)

    assert [r["title"] for r in result] == ["Statistik Pendidikan Tinggi 2024"]
