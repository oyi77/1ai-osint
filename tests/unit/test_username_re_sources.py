"""Tests for the keyless RE username-lookup source adapters (0-API mode).

Covers: huggingface (username), scratch (username), itchio (username),
codeforces (username).

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
# HuggingFaceSource
# ---------------------------------------------------------------------------
class TestHuggingFaceSource:
    def _make_source(self):
        from src.modules.sources.huggingface_source import HuggingFaceSource

        return HuggingFaceSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_with_full_name(self):
        """Username -> profile presence + `name (full name)` title parse."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html><head><title>osanseviero (Omar Sanseviero)</title></head></html>"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("huggingface_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("OsanSeviero")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "huggingface" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {"huggingface: osanseviero", "full name: Omar Sanseviero"}

    @pytest.mark.asyncio
    async def test_search_for_address_title_not_username(self):
        """Title that differs from the username becomes a profile-title leak."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<title>alice's models</title>"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("huggingface_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        texts = {leak.text for leak in leaks}
        assert texts == {"huggingface: alice", "profile title: alice's models"}

    @pytest.mark.asyncio
    async def test_search_for_address_title_equals_username_no_extra(self):
        """Title identical to the username adds no duplicate leak."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<title>alice</title>"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("huggingface_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 1
        assert leaks[0].text == "huggingface: alice"

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("huggingface_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("A!")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 404
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("huggingface_source", mock_client))
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
        patches = _enter_patches(_patch_source("huggingface_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# ScratchSource
# ---------------------------------------------------------------------------
class TestScratchSource:
    def _make_source(self):
        from src.modules.sources.scratch_source import ScratchSource

        return ScratchSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """Username -> Scratch profile presence leak."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("scratch_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("Alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 1
        assert all(leak.source_name == "scratch" for leak in leaks)
        assert {leak.text for leak in leaks} == {"scratch: alice"}

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("scratch_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("a")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 404
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("scratch_source", mock_client))
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
        patches = _enter_patches(_patch_source("scratch_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# ItchIoSource
# ---------------------------------------------------------------------------
class TestItchIoSource:
    def _make_source(self):
        from src.modules.sources.itchio_source import ItchIoSource

        return ItchIoSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success_with_title(self):
        """Username -> profile presence + page title leak."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<title>alice's profile - itch.io</title>"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("itchio_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("Alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 2
        assert all(leak.source_name == "itchio" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {"itchio: alice", "profile title: alice's profile - itch.io"}

    @pytest.mark.asyncio
    async def test_title_equals_username_no_extra(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<title>alice</title>"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("itchio_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 1
        assert leaks[0].text == "itchio: alice"

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("itchio_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("A!")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 404
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("itchio_source", mock_client))
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
        patches = _enter_patches(_patch_source("itchio_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# CodeforcesSource
# ---------------------------------------------------------------------------
class TestCodeforcesSource:
    def _make_source(self):
        from src.modules.sources.codeforces_source import CodeforcesSource

        return CodeforcesSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        """Username -> handle / rating / rank / max rating / registered leaks."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "status": "OK",
            "result": [
                {
                    "handle": "alice",
                    "rating": 1500,
                    "rank": "specialist",
                    "maxRating": 1700,
                    "registrationTimeSeconds": 1615766400,
                }
            ],
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("codeforces_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("Alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "codeforces" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "codeforces: alice",
            "rating: 1500",
            "rank: specialist",
            "max rating: 1700",
            "registered: 2021-03-15",
        }

    @pytest.mark.asyncio
    async def test_status_failed_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": "FAILED", "comment": "handle not found"}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("codeforces_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("codeforces_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("a!")
        finally:
            _exit_patches(patches)
        assert leaks == []
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 500
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("codeforces_source", mock_client))
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
        patches = _enter_patches(_patch_source("codeforces_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []
