"""Tests for government open-data intel adapters (blueprint Phase 2 — S5).

Covers PANDI RDAP parsing + data.go.id flight-data extraction. External
calls are mocked — no real network (repo convention).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.modules.deep_scan.free_intel_adapter import (
    _run_data_go_id_intel,
    _run_pandi_whois_intel,
)
from src.modules.free_intel.data_go_id_intel import DataGoIdIntel
from src.modules.free_intel.pandi_whois_intel import (
    PandiWhoisIntel,
    parse_rdap_response,
)

# ── PANDI RDAP ──────────────────────────────────────────────────────────────


def _rdap_payload() -> dict:
    return {
        "rdapConformance": ["rdap_level_0"],
        "ldhName": "example.co.id",
        "status": ["active", "client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2015-06-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-06-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "ns1.example.co.id"},
            {"ldhName": "ns2.example.co.id"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Budi Santoso"],
                        ["org", {}, "text", "PT Contoh Indonesia"],
                    ],
                ],
            }
        ],
    }


def test_parse_rdap_response_full():
    rec = parse_rdap_response("example.co.id", _rdap_payload())
    assert rec.domain == "example.co.id"
    assert rec.registrant_name == "Budi Santoso"
    assert rec.registrant_org == "PT Contoh Indonesia"
    assert rec.created == "2015-06-01T00:00:00Z"
    assert rec.expires == "2027-06-01T00:00:00Z"
    assert "active" in rec.status
    assert rec.nameservers == ["ns1.example.co.id", "ns2.example.co.id"]


def test_parse_rdap_response_tolerates_partial_payload():
    rec = parse_rdap_response("or.id", {"ldhName": "yayasan.or.id"})
    assert rec.registrant_name == ""
    assert rec.registrant_org == ""
    assert rec.created == ""
    assert rec.nameservers == []
    assert rec.status == []


def test_parse_rdap_falls_back_to_other_entities_for_org():
    payload = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrar Jaya"]],
                ],
            }
        ]
    }
    rec = parse_rdap_response("x.web.id", payload)
    assert rec.registrant_org == "Registrar Jaya"


@pytest.mark.asyncio
async def test_pandi_lookup_returns_none_for_non_id_domain():
    scanner = PandiWhoisIntel()
    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()
        result = await scanner.lookup("example.com")
        assert result is None
        mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_pandi_lookup_parses_http_200():
    scanner = PandiWhoisIntel()

    async def fake_get(url, headers=None):
        class _Resp:
            status_code = 200

            def json(self):
                return _rdap_payload()

        return _Resp()

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = fake_get
    with patch("httpx.AsyncClient", return_value=mock_client):
        rec = await scanner.lookup("example.co.id")
        assert rec is not None
        assert rec.registrant_org == "PT Contoh Indonesia"


@pytest.mark.asyncio
async def test_pandi_lookup_returns_none_on_non_200():
    scanner = PandiWhoisIntel()

    class _Resp:
        status_code = 404

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = AsyncMock(return_value=_Resp())
    with patch("httpx.AsyncClient", return_value=mock_client):
        rec = await scanner.lookup("missing.co.id")
        assert rec is None


@pytest.mark.asyncio
async def test_pandi_lookup_uses_rdap_path_prefix():
    """The RDAP endpoint must include the /rdap/ path segment (IANA bootstrap).

    Regression guard: the endpoint previously lacked the path segment, which
    made every live lookup return 404 (verified against rdap.pandi.id).
    """
    scanner = PandiWhoisIntel()
    captured: list[str] = []

    async def fake_get(url, headers=None):
        captured.append(url)

        class _Resp:
            status_code = 200

            def json(self):
                return _rdap_payload()

        return _Resp()

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = fake_get
    with patch("httpx.AsyncClient", return_value=mock_client):
        await scanner.lookup("example.co.id")
    assert captured, "lookup should have issued an HTTP request"
    assert captured[0] == "https://rdap.pandi.id/rdap/domain/example.co.id"


@pytest.mark.asyncio
async def test_run_pandi_whois_intel_builds_findings():
    with patch(
        "src.modules.free_intel.pandi_whois_intel.PandiWhoisIntel.lookup",
        new=AsyncMock(return_value=parse_rdap_response("example.co.id", _rdap_payload())),
    ):
        result = await _run_pandi_whois_intel("example.co.id")
    assert result is not None
    assert result.module == "free_pandi_whois"
    assert len(result.findings) == 2  # registrant + nameservers
    assert result.findings[0].raw_data["registrant_org"] == "PT Contoh Indonesia"
    assert "pandi" in result.findings[0].tags


@pytest.mark.asyncio
async def test_run_pandi_whois_intel_none_on_no_data():
    with patch(
        "src.modules.free_intel.pandi_whois_intel.PandiWhoisIntel.lookup",
        new=AsyncMock(return_value=parse_rdap_response("x.web.id", {"ldhName": "x.web.id"})),
    ):
        result = await _run_pandi_whois_intel("x.web.id")
    assert result is None  # no registrant, no nameservers → no findings


# ── data.go.id ──────────────────────────────────────────────────────────────

_FLIGHT_SAMPLE = (
    '<script>self.__next_f.push([1,"\\"title\\":\\"Jumlah Penduduk Indonesia 2025\\""])</script>'
    '<script>self.__next_f.push([1,"\\"title\\":\\"kategori\\""])</script>'
    '<script>self.__next_f.push([1,"\\"nama_organisasi\\":\\"BPS\\""])</script>'
)


@pytest.mark.asyncio
async def test_data_go_id_search_extracts_dataset_titles():
    scanner = DataGoIdIntel()

    class _Resp:
        status_code = 200
        text = _FLIGHT_SAMPLE

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = AsyncMock(return_value=_Resp())
    with patch("httpx.AsyncClient", return_value=mock_client):
        datasets = await scanner.search_datasets("penduduk")

    assert any(d["title"] == "Jumlah Penduduk Indonesia 2025" for d in datasets)
    # "kategori" (UI chrome) must be filtered out
    assert not any(d["title"] == "kategori" for d in datasets)


@pytest.mark.asyncio
async def test_data_go_id_search_non_200_returns_empty():
    scanner = DataGoIdIntel()

    class _Resp:
        status_code = 503
        text = ""

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = AsyncMock(return_value=_Resp())
    with patch("httpx.AsyncClient", return_value=mock_client):
        datasets = await scanner.search_datasets("penduduk")
    assert datasets == []


@pytest.mark.asyncio
async def test_run_data_go_id_intel_builds_findings():
    scanner_datasets = [{"title": "Jumlah Penduduk Indonesia 2025", "organization": "BPS"}]
    with patch(
        "src.modules.free_intel.data_go_id_intel.DataGoIdIntel.search_datasets",
        new=AsyncMock(return_value=scanner_datasets),
    ):
        result = await _run_data_go_id_intel("penduduk")
    assert result is not None
    assert result.module == "free_data_go_id"
    assert len(result.findings) == 1
    assert "government" in result.findings[0].tags
    assert result.metadata["dataset_count"] == 1


@pytest.mark.asyncio
async def test_run_data_go_id_intel_none_on_empty():
    with patch(
        "src.modules.free_intel.data_go_id_intel.DataGoIdIntel.search_datasets",
        new=AsyncMock(return_value=[]),
    ):
        result = await _run_data_go_id_intel("tidak-ada")
    assert result is None
