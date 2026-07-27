from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.free_intel.pddikti_intel import PDDIKTIIntel


@pytest.mark.asyncio
async def test_pddikti_search_success():
    intel = PDDIKTIIntel()
    mock_html = """
    <span class="result__snippet">Nama: John Doe, PT : Universitas Indonesia, Prodi : Ilmu Komputer, NIM: 12345</a
    <span class="result__snippet">Nama: John Doe, Perguruan Tinggi : Institut Teknologi Bandung, Program Studi : Teknik Informatika</a
    <span class="result__snippet">Nama: John Doe, PT : Universitas Indonesia, Prodi : Ilmu Komputer, NIM: 12345</a
    """
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.text = mock_html
        client.post = AsyncMock(return_value=resp)

        results = await intel.search("John Doe")
        assert len(results) == 2
        assert results[0].university == "Universitas Indonesia"
        assert results[0].major == "Ilmu Komputer"
        assert results[1].university == "Institut Teknologi Bandung"
        assert results[1].major == "Teknik Informatika"


@pytest.mark.asyncio
async def test_pddikti_search_fallback_heuristic():
    intel = PDDIKTIIntel()
    mock_html = """
    <span class="result__snippet">John Doe is studying at Universitas Indonesia, major in chemistry</a
    """
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.text = mock_html
        client.post = AsyncMock(return_value=resp)

        results = await intel.search("John Doe")
        assert len(results) == 1
        assert results[0].university == "Universitas Indonesia"


@pytest.mark.asyncio
async def test_pddikti_search_exception():
    intel = PDDIKTIIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        client.post = AsyncMock(side_effect=Exception("DDG error"))

        results = await intel.search("John Doe")
        assert results == []
