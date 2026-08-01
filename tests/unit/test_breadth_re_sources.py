"""Tests for the breadth-audit keyless RE source adapters (0-API mode).

Covers: bgpview, certspotter, rapiddns, anubis, urlscan.

All tests are mocked — no live network calls (repo convention).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _mock_client(responses):
    """Return a mock AsyncClient that yields responses in order."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=responses)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


def _patch_source(module, mock_client):
    """Context manager patching httpx.AsyncClient, asyncio.sleep, time.monotonic."""
    return (
        patch(f"src.modules.sources.{module}.httpx.AsyncClient", return_value=mock_client),
        patch(f"src.modules.sources.{module}.asyncio.sleep", new_callable=AsyncMock),
        patch(f"src.modules.sources.{module}.time.monotonic", return_value=0.0),
    )


def _enter_patches(patch_list):
    for p in patch_list:
        p.start()
    return patch_list


def _exit_patches(patch_list):
    for p in reversed(patch_list):
        p.stop()


# ---------------------------------------------------------------------------
# BgpViewSource
# ---------------------------------------------------------------------------
class TestBgpViewSource:
    def _make_source(self):
        from src.modules.sources.bgpview_source import BgpViewSource

        return BgpViewSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """IP -> ASN / prefix / RIR / country leaks."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {
                "ip": "8.8.8.8",
                "asn": {"asn": 15169, "name": "GOOGLE", "description": "Google LLC"},
                "prefixes": [{"prefix": "8.8.8.0/24"}],
                "rir_allocation": {"rir_name": "arin"},
                "location": {"country": "United States"},
            }
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("bgpview_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("8.8.8.8")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "bgpview" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert "asn: 15169" in texts
        assert "asn name: GOOGLE / Google LLC" in texts
        assert "prefix: 8.8.8.0/24" in texts
        assert "rir: arin" in texts
        assert "country: United States" in texts

    @pytest.mark.asyncio
    async def test_search_for_address_non_ip_no_http(self):
        """Non-IP input -> empty result without making any HTTP call."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=MagicMock(status_code=200))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("bgpview_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 429
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("bgpview_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("8.8.8.8")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("bgpview_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("8.8.8.8")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# CertSpotterSource
# ---------------------------------------------------------------------------
class TestCertSpotterSource:
    def _make_source(self):
        from src.modules.sources.certspotter_source import CertSpotterSource

        return CertSpotterSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_dedup(self):
        """dns_names are lowercased, dot-stripped, and deduped."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [
            {
                "id": 1,
                "dns_names": ["example.com", "www.example.com", "WWW.EXAMPLE.COM."],
            }
        ]
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("certspotter_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "certspotter" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {"example.com", "www.example.com"}

    @pytest.mark.asyncio
    async def test_search_for_address_empty_json_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = []
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("certspotter_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("nonexistent.invalid")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 500
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("certspotter_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("certspotter_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# RapidDnsSource
# ---------------------------------------------------------------------------
class TestRapidDnsSource:
    def _make_source(self):
        from src.modules.sources.rapiddns_source import RapidDnsSource

        return RapidDnsSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_strips_tags(self):
        """HTML table cells are extracted, stripped, and matched to the domain."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<table><tr>"
            "<td>www.example.com</td>"
            '<td><a href="/dns/example.com">example.com</a></td>'
            "<td>unrelated.org</td>"
            "</tr></table>"
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("rapiddns_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "rapiddns" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {"www.example.com", "example.com"}

    @pytest.mark.asyncio
    async def test_search_for_address_empty_domain_no_http(self):
        """Empty domain -> empty result without making any HTTP call."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=MagicMock(status_code=200))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("rapiddns_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("   ")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 404
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("rapiddns_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("rapiddns_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# AnubisSource
# ---------------------------------------------------------------------------
class TestAnubisSource:
    def _make_source(self):
        from src.modules.sources.anubis_source import AnubisSource

        return AnubisSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_dedup(self):
        """JSON array names are lowercased, dot-stripped, and deduped."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = ["a.example.com", "a.example.com", "b.Example.com."]
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("anubis_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "anubis" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {"a.example.com", "b.example.com"}

    @pytest.mark.asyncio
    async def test_search_for_address_empty_domain_no_http(self):
        """Empty domain -> empty result without making any HTTP call."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=MagicMock(status_code=200))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("anubis_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 500
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("anubis_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("anubis_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# UrlScanSource
# ---------------------------------------------------------------------------
class TestUrlScanSource:
    def _make_source(self):
        from src.modules.sources.urlscan_source import UrlScanSource

        return UrlScanSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """URL + ip/ASN leaks from page payloads."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "results": [{"page": {"url": "https://sub.example.com/x", "ip": "1.2.3.4", "asn": "AS15169"}}]
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("urlscan_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "urlscan" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert "url: https://sub.example.com/x" in texts
        assert "ip: 1.2.3.4 (AS15169)" in texts

    @pytest.mark.asyncio
    async def test_search_for_address_duplicate_url_and_ip_deduped(self):
        """Same URL and same ip+asn pair appear only once."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "results": [
                {"page": {"url": "https://a.example.com/1", "ip": "1.2.3.4", "asn": "AS15169"}},
                {"page": {"url": "https://a.example.com/1", "ip": "1.2.3.4", "asn": "AS15169"}},
            ]
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("urlscan_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2

    @pytest.mark.asyncio
    async def test_search_for_address_bad_json_never_raises(self):
        """Malformed JSON body -> empty result, no exception."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("bad json")
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("urlscan_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 429
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("urlscan_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("urlscan_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []
