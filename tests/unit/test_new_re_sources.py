"""Tests for the 5 keyless RE source adapters (0-API mode).

Covers: hackertarget, dns_records, mempool, ip_api, pgp_keys.

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
# HackerTargetSource
# ---------------------------------------------------------------------------
class TestHackerTargetSource:
    def _make_source(self):
        from src.modules.sources.hackertarget_source import HackerTargetSource

        return HackerTargetSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_domain_hostsearch(self):
        """Domain -> /hostsearch CSV lines become host -> ip leaks."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "sub.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("hackertarget_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "hackertarget" for leak in leaks)
        assert leaks[0].text == "sub.example.com -> 1.2.3.4"
        assert leaks[1].text == "www.example.com -> 5.6.7.8"
        assert leaks[0].source_url.startswith("https://api.hackertarget.com/hostsearch/")

    @pytest.mark.asyncio
    async def test_search_for_address_domain_skips_error_lines(self):
        """Error / malformed lines are skipped, valid ones kept."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "error: api count exceeded\nok.example.com,9.9.9.9\n"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("hackertarget_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 1
        assert leaks[0].text == "ok.example.com -> 9.9.9.9"

    @pytest.mark.asyncio
    async def test_search_for_address_ip_reverseiplookup(self):
        """IPv4 -> /reverseiplookup lines become hostname leaks."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "host1.example.com\napi count exceeded\nhost2.example.com\n"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("hackertarget_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("8.8.8.8")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "hackertarget" for leak in leaks)
        assert leaks[0].text == "host1.example.com"
        assert leaks[1].text == "host2.example.com"
        assert leaks[0].source_url.startswith("https://api.hackertarget.com/reverseiplookup/")

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 500
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("hackertarget_source", mock_client))
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
        patches = _enter_patches(_patch_source("hackertarget_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# DnsRecordsSource
# ---------------------------------------------------------------------------
class TestDnsRecordsSource:
    def _make_source(self):
        from src.modules.sources.dns_records_source import DnsRecordsSource

        return DnsRecordsSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """Answer entries (JSON int types) are labeled and deduped."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "Answer": [
                {"name": "example.com", "type": 1, "TTL": 300, "data": "93.184.216.34"},
                {"name": "example.com", "type": 2, "TTL": 300, "data": "ns1.example.com."},
                {"name": "example.com", "type": 16, "TTL": 300, "data": "v=spf1 -all"},
            ]
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("dns_records_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 3
        assert all(leak.source_name == "dns_records" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert "A 93.184.216.34 (TTL 300)" in texts
        assert "NS ns1.example.com. (TTL 300)" in texts
        assert "TXT v=spf1 -all (TTL 300)" in texts

    @pytest.mark.asyncio
    async def test_search_for_address_empty_answer_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Status": 0, "Answer": []}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("dns_records_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("nonexistent.invalid")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 400
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("dns_records_source", mock_client))
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
        patches = _enter_patches(_patch_source("dns_records_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# MempoolSource
# ---------------------------------------------------------------------------
class TestMempoolSource:
    def _make_source(self):
        from src.modules.sources.mempool_source import MempoolSource

        return MempoolSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_two_calls(self):
        """Summary + txs: 2 HTTP calls per search, both contribute leaks."""
        summary_resp = MagicMock()
        summary_resp.status_code = 200
        summary_resp.json.return_value = {
            "chain_stats": {
                "funded_txo_sum": 100000,
                "spent_txo_sum": 50000,
                "tx_count": 10,
                "funded_txo_count": 5,
            },
            "mempool_stats": {"tx_count": 2},
        }
        txs_resp = MagicMock()
        txs_resp.status_code = 200
        txs_resp.json.return_value = [{"txid": "abc123", "vin": [{"prevout": {"value": 1234}}]}]
        mock_client = _mock_client([summary_resp, txs_resp])
        patches = _enter_patches(_patch_source("mempool_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("bc1qexample")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 4
        assert all(leak.source_name == "mempool" for leak in leaks)
        assert any("funded 100000 sats" in leak.text for leak in leaks)
        assert any(leak.text == "Funded UTXOs: 5" for leak in leaks)
        assert any(leak.text == "Unconfirmed txs: 2" for leak in leaks)
        assert any("TX abc123 (1234 sats in)" in leak.text for leak in leaks)

    @pytest.mark.asyncio
    async def test_search_for_address_bad_summary_good_txs(self):
        """Summary non-200 but txs 200 -> tx leaks still produced."""
        summary_resp = MagicMock()
        summary_resp.status_code = 500
        txs_resp = MagicMock()
        txs_resp.status_code = 200
        txs_resp.json.return_value = [{"txid": "def456", "vin": []}]
        mock_client = _mock_client([summary_resp, txs_resp])
        patches = _enter_patches(_patch_source("mempool_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("bc1qexample")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 1
        assert leaks[0].text == "TX def456 (0 sats in)"

    @pytest.mark.asyncio
    async def test_search_for_address_all_non_200_returns_empty(self):
        summary_resp = MagicMock()
        summary_resp.status_code = 404
        txs_resp = MagicMock()
        txs_resp.status_code = 404
        mock_client = _mock_client([summary_resp, txs_resp])
        patches = _enter_patches(_patch_source("mempool_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("bc1qexample")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("mempool_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("bc1qexample")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# IpApiSource
# ---------------------------------------------------------------------------
class TestIpApiSource:
    def _make_source(self):
        from src.modules.sources.ip_api_source import IpApiSource

        return IpApiSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "status": "success",
            "country": "United States",
            "city": "Mountain View",
            "isp": "Google LLC",
            "query": "8.8.8.8",
            "proxy": False,
            "hosting": True,
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("ip_api_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("8.8.8.8")
        finally:
            _exit_patches(patches)
        assert len(leaks) >= 3
        assert all(leak.source_name == "ip_api" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert "country: United States" in texts
        assert "city: Mountain View" in texts
        assert "isp: Google LLC" in texts

    @pytest.mark.asyncio
    async def test_search_for_address_status_not_success_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": "fail", "message": "invalid query"}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("ip_api_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("not-an-ip")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 429
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("ip_api_source", mock_client))
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
        patches = _enter_patches(_patch_source("ip_api_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("8.8.8.8")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# PgpKeysSource
# ---------------------------------------------------------------------------
class TestPgpKeysSource:
    def _make_source(self):
        from src.modules.sources.pgp_keys_source import PgpKeysSource

        return PgpKeysSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc123\n-----END PGP PUBLIC KEY BLOCK-----\n"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("pgp_keys_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("Alice@Example.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 1
        assert leaks[0].source_name == "pgp_keys"
        assert "BEGIN PGP PUBLIC KEY BLOCK" in leaks[0].text

    @pytest.mark.asyncio
    async def test_search_for_address_without_at_no_http(self):
        """No '@' -> empty result without making any HTTP call."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=MagicMock(status_code=200))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("pgp_keys_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("not-an-email")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_search_for_address_404_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "not found"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("pgp_keys_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("nobody@example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_200_without_pgp_block_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "plain text, not a key"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("pgp_keys_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("nobody@example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception_never_raises(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        patches = _enter_patches(_patch_source("pgp_keys_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("nobody@example.com")
        finally:
            _exit_patches(patches)
        assert leaks == []
