"""Tests for the P1-gap keyless RE source adapters (0-API mode).

Covers: proxynova (breach), veriphone (phone), keybase (username).

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
# ProxynovaSource
# ---------------------------------------------------------------------------
class TestProxynovaSource:
    def _make_source(self):
        from src.modules.sources.proxynova_source import ProxynovaSource

        return ProxynovaSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_dedupes(self):
        """Email query -> deduped `domain | line` breach leaks."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {
                "dom.com": [{"line": "line1"}, {"line": "line1"}, {"line": "line2"}],
                "other.net": [{"line": "line3"}],
            }
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("proxynova_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("victim@dom.com")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 3
        assert all(leak.source_name == "proxynova" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {"dom.com | line1", "dom.com | line2", "other.net | line3"}

    @pytest.mark.asyncio
    async def test_invalid_input_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("proxynova_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("   ")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 500
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("proxynova_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("victim@dom.com")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_exception_never_raises(self):
        mock_client = _mock_client([])
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        patches = _enter_patches(_patch_source("proxynova_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("victim@dom.com")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# VeriPhoneSource
# ---------------------------------------------------------------------------
class TestVeriPhoneSource:
    def _make_source(self):
        from src.modules.sources.veriphone_source import VeriPhoneSource

        return VeriPhoneSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """Phone -> carrier / line type / country / formatting leaks."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "status": "success",
            "phone_valid": True,
            "carrier": "T-Mobile",
            "line_type": "mobile",
            "country": "United States",
            "country_prefix": "+1",
            "international_format": "+1 202-555-0100",
            "national_format": "(202) 555-0100",
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("veriphone_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("+12025550100")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "veriphone" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "carrier: T-Mobile",
            "line type: mobile",
            "country: United States (+1)",
            "international: +1 202-555-0100",
            "national: (202) 555-0100",
        }

    @pytest.mark.asyncio
    async def test_invalid_phone_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("veriphone_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("abc")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_phone_too_few_digits_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("veriphone_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("1234")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_phone_invalid_in_response_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": "success", "phone_valid": False}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("veriphone_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("+12025550100")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 429
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("veriphone_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("+12025550100")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_exception_never_raises(self):
        mock_client = _mock_client([])
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        patches = _enter_patches(_patch_source("veriphone_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("+12025550100")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# KeybaseSource
# ---------------------------------------------------------------------------
class TestKeybaseSource:
    def _make_source(self):
        from src.modules.sources.keybase_source import KeybaseSource

        return KeybaseSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """Username -> keybase handle / full name / bio / location / site / avatar."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "status": {"code": 0, "name": "OK"},
            "them": [
                {
                    "basics": {"username": "alice", "full_name": "Alice Smith"},
                    "profile": {
                        "bio": "Privacy engineer",
                        "location": "Berlin",
                        "site": "https://alice.example",
                    },
                    "pictures": {"primary": {"url": "https://alice.example/avatar.png"}},
                }
            ],
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("Alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 6
        assert all(leak.source_name == "keybase" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "keybase: alice",
            "full name: Alice Smith",
            "bio: Privacy engineer",
            "location: Berlin",
            "site: https://alice.example",
            "avatar: https://alice.example/avatar.png",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("A!")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_username_too_long_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("a" * 17)
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_status_code_nonzero_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": {"code": 201}, "them": []}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_empty_them_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": {"code": 0}, "them": []}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 500
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_exception_never_raises(self):
        mock_client = _mock_client([])
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        patches = _enter_patches(_patch_source("keybase_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []
