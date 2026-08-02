"""Tests for the keyless RE username-lookup source adapters (0-API mode).

Covers: huggingface (username), scratch (username), itchio (username),
codeforces (username), devto (username), steam (username), chess (username),
letterboxd (username), medium (username), pastebin (username),
youtube (username), fandom (username).

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


# ---------------------------------------------------------------------------
# DevToSource
# ---------------------------------------------------------------------------
class TestDevToSource:
    def _make_source(self):
        from src.modules.sources.devto_source import DevToSource

        return DevToSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<title>Alice Smith - DEV Community</title>"
            '<meta name="description" content="Writes about tech.">'
            '<time datetime="2020-05-01T10:00:00Z">'
            '"sameAs":["https://twitter.com/alice","notaurl"]'
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("devto_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("Alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "devto" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "devto: alice",
            "profile title: Alice Smith",
            "description: Writes about tech.",
            "joined: 2020-05-01T10:00:00Z",
            "social link: https://twitter.com/alice",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("devto_source", mock_client))
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
        patches = _enter_patches(_patch_source("devto_source", mock_client))
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
        patches = _enter_patches(_patch_source("devto_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# SteamSource
# ---------------------------------------------------------------------------
class TestSteamSource:
    def _make_source(self):
        from src.modules.sources.steam_source import SteamSource

        return SteamSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<profile><personaname>Alice</personaname>"
            "<steamID64>76561198000000000</steamID64>"
            "<memberSince>2020</memberSince>"
            "<realname>Alice Smith</realname>"
            "<location>Earth</location>"
            "<summary>bio</summary>"
            "<vacBanned>0</vacBanned>"
            "<tradeBanState>None</tradeBanState></profile>"
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("steam_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 7
        assert all(leak.source_name == "steam" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "steam: alice",
            "display name: Alice",
            "steam64 id: 76561198000000000",
            "member since: 2020",
            "real name: Alice Smith",
            "location: Earth",
            "summary: bio",
        }

    @pytest.mark.asyncio
    async def test_error_body_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<error>No match</error>"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("steam_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_combined_bans_leaks(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<profile><personaname>Alice</personaname>"
            "<vacBanned>1</vacBanned>"
            "<tradeBanState>Banned</tradeBanState></profile>"
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("steam_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 4
        texts = {leak.text for leak in leaks}
        assert texts == {
            "steam: alice",
            "display name: Alice",
            "vac banned: 1",
            "trade ban: Banned",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("steam_source", mock_client))
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
        patches = _enter_patches(_patch_source("steam_source", mock_client))
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
        patches = _enter_patches(_patch_source("steam_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# ChessSource
# ---------------------------------------------------------------------------
class TestChessSource:
    def _make_source(self):
        from src.modules.sources.chess_source import ChessSource

        return ChessSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            '<span class="cc-user-title-component">GM</span>'
            '<div class="profile-card-name">Alice Smith</div>'
            '<div class="profile-card-location">New York</div>'
            '<div class="profile-header-details-value">Mar 2020</div>'
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("chess_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "chess" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "chess: alice",
            "chess title: GM",
            "full name: Alice Smith",
            "location: New York",
            "joined: Mar 2020",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("chess_source", mock_client))
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
        patches = _enter_patches(_patch_source("chess_source", mock_client))
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
        patches = _enter_patches(_patch_source("chess_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# LetterboxdSource
# ---------------------------------------------------------------------------
class TestLetterboxdSource:
    def _make_source(self):
        from src.modules.sources.letterboxd_source import LetterboxdSource

        return LetterboxdSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<title>Alice Smith's profile \u2022 Letterboxd</title>"
            '<meta name="description" content="Reviews and lists.">'
            '<a class="external-link" href="https://twitter.com/alice">'
            "Member since</span><span>2020</span>"
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("letterboxd_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "letterboxd" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "letterboxd: alice",
            "profile title: Alice Smith",
            "description: Reviews and lists.",
            "external link: https://twitter.com/alice",
            "member since: 2020",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("letterboxd_source", mock_client))
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
        patches = _enter_patches(_patch_source("letterboxd_source", mock_client))
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
        patches = _enter_patches(_patch_source("letterboxd_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# MediumSource
# ---------------------------------------------------------------------------
class TestMediumSource:
    def _make_source(self):
        from src.modules.sources.medium_source import MediumSource

        return MediumSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '<meta name="description" content="Read writing from Alice Smith on Medium. I write about tech.">'
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("medium_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 3
        assert all(leak.source_name == "medium" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "medium: alice",
            "profile title: Alice Smith",
            "description:  I write about tech.",
        }

    @pytest.mark.asyncio
    async def test_cf_challenge_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>x</html>"
        resp.headers = {"cf-mitigated": "challenge"}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("medium_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_soft_404_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "PAGE NOT FOUND"
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("medium_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_403_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 403
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("medium_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("medium_source", mock_client))
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
        patches = _enter_patches(_patch_source("medium_source", mock_client))
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
        patches = _enter_patches(_patch_source("medium_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# PastebinSource
# ---------------------------------------------------------------------------
class TestPastebinSource:
    def _make_source(self):
        from src.modules.sources.pastebin_source import PastebinSource

        return PastebinSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '<title>Alice\'s Pastebin - Pastebin.com</title><span class="date-text" title="05-01-2020"></span>'
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("pastebin_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 3
        assert all(leak.source_name == "pastebin" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "pastebin: alice",
            "profile title: Alice",
            "joined: 05-01-2020",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("pastebin_source", mock_client))
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
        patches = _enter_patches(_patch_source("pastebin_source", mock_client))
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
        patches = _enter_patches(_patch_source("pastebin_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# YoutubeSource
# ---------------------------------------------------------------------------
class TestYoutubeSource:
    def _make_source(self):
        from src.modules.sources.youtube_source import YoutubeSource

        return YoutubeSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "<title>Alice Smith - YouTube</title>"
            '<meta name="description" content="bio here">'
            '"joinedDateText":{"content":"May 1, 2020"}'
            '"country":{"simpleText":"United States"}'
        )
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("youtube_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 5
        assert all(leak.source_name == "youtube" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "youtube: alice",
            "profile title: Alice Smith",
            "description: bio here",
            "joined: May 1, 2020",
            "country: United States",
        }

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("youtube_source", mock_client))
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
        patches = _enter_patches(_patch_source("youtube_source", mock_client))
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
        patches = _enter_patches(_patch_source("youtube_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []


# ---------------------------------------------------------------------------
# FandomSource
# ---------------------------------------------------------------------------
class TestFandomSource:
    def _make_source(self):
        from src.modules.sources.fandom_source import FandomSource

        return FandomSource(request_delay=0.0, timeout=5.0)

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
            "query": {
                "users": [
                    {
                        "userid": 123,
                        "name": "Alice",
                        "registration": "2019-05-01T12:34:56Z",
                        "editcount": 42,
                        "groups": ["sysop", "editor"],
                        "gender": "female",
                    }
                ]
            }
        }
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("fandom_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert len(leaks) == 6
        assert all(leak.source_name == "fandom" for leak in leaks)
        texts = {leak.text for leak in leaks}
        assert texts == {
            "fandom: alice",
            "fandom user id: 123",
            "registered: 2019-05-01",
            "edit count: 42",
            "groups: sysop, editor",
            "gender: female",
        }

    @pytest.mark.asyncio
    async def test_missing_user_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"query": {"users": [{"name": "Alice", "missing": ""}]}}
        mock_client = _mock_client([resp])
        patches = _enter_patches(_patch_source("fandom_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_invalid_username_no_http(self):
        mock_client = _mock_client([])
        patches = _enter_patches(_patch_source("fandom_source", mock_client))
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
        patches = _enter_patches(_patch_source("fandom_source", mock_client))
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
        patches = _enter_patches(_patch_source("fandom_source", mock_client))
        try:
            source = self._make_source()
            leaks = await source.search_for_address("alice")
        finally:
            _exit_patches(patches)
        assert leaks == []
