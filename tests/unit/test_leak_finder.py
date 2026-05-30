"""Tests for leak finder coordinator and source adapters."""
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.crypto.leak_finder.extractor import ExtractedKey, KeyType
from src.modules.crypto.leak_finder.sources.github_source import GitHubLeakSource, RawLeak

class TestRawLeak:
    def test_creation(self):
        leak = RawLeak(text="test", source_name="github", source_url="https://example.com")
        assert leak.text == "test"
        assert leak.source_name == "github"
        assert isinstance(leak.timestamp, datetime)

    def test_default_timestamp(self):
        leak = RawLeak(text="x", source_name="test")
        assert abs((datetime.now(timezone.utc) - leak.timestamp).total_seconds()) < 5

class TestGitHubLeakSource:
    def test_init_with_token(self):
        source = GitHubLeakSource(github_token="ghp_test")
        assert source.github_token == "ghp_test"
        assert source.rate_limit == 30

    def test_init_without_token(self):
        source = GitHubLeakSource()
        assert source.github_token == ""
        assert source.rate_limit == 10

    def test_make_headers_with_token(self):
        headers = GitHubLeakSource(github_token="ghp_abc")._make_headers()
        assert headers["Authorization"] == "token ghp_abc"

    def test_make_headers_without_token(self):
        assert "Authorization" not in GitHubLeakSource()._make_headers()

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_mock(self):
        source = GitHubLeakSource(github_token="test")
        mock_search = MagicMock()
        mock_search.status_code = 200
        mock_search.json.return_value = {"items": [{"html_url": "https://github.com/user/repo/blob/main/.env"}]}
        mock_search.raise_for_status = MagicMock()
        mock_raw = MagicMock()
        mock_raw.text = "PRIVATE_KEY=" + "ab" * 32
        mock_raw.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_search, mock_raw])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.crypto.leak_finder.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            leaks = await source.fetch_raw_leaks(queries=['test'], max_per_query=1)
        assert len(leaks) == 1
        assert leaks[0].source_name == "github"

    @pytest.mark.asyncio
    async def test_rate_limit_backoff_on_403(self):
        source = GitHubLeakSource(github_token="test")
        mock_403 = MagicMock()
        mock_403.status_code = 403
        mock_403.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_403)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.crypto.leak_finder.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.crypto.leak_finder.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(queries=["test"], max_per_query=1)
        assert len(leaks) == 0

class TestPasteSource:
    def test_parse_pastebin_ids(self):
        from src.modules.crypto.leak_finder.sources.paste_source import PasteSource
        html = '<a href="/abc123DEF">Paste 1</a><a href="/archive">Archive</a><a href="/login">Login</a>'
        ids = PasteSource._parse_pastebin_ids(html)
        assert "abc123DEF" in ids
        assert "archive" not in ids

class TestTelegramSource:
    def test_extract_flood_wait(self):
        from src.modules.crypto.leak_finder.sources.telegram_source import TelegramSource
        assert TelegramSource._extract_flood_wait("A wait of 30 seconds is required") == 30
        assert TelegramSource._extract_flood_wait("unknown error") == 60

class TestLeakFinderCoordinator:
    @pytest.fixture
    def mock_key(self):
        return ExtractedKey(
            key_raw="a" * 64, key_type=KeyType.HEX_PRIVATE_KEY, key_hex="a" * 64,
            derived_addresses={"Ethereum": "0x1234567890abcdef1234567890abcdef12345678"},
        )

    @pytest.mark.asyncio
    async def test_run_once_empty_sources(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=["github"])
        with patch.object(coordinator, "_fetch_all_sources", new_callable=AsyncMock, return_value=[]):
            with patch.object(coordinator, "_check_balances", new_callable=AsyncMock, return_value=[]):
                result = await coordinator.run_once()
        assert result.raw_leaks_fetched == 0
        assert result.keys_extracted == 0

    @pytest.mark.asyncio
    async def test_run_once_with_leaks(self, mock_key):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=["github"])
        raw_leaks = [RawLeak(text="test", source_name="github")]
        with patch.object(coordinator, "_fetch_all_sources", new_callable=AsyncMock, return_value=raw_leaks):
            with patch("src.modules.crypto.leak_finder.coordinator.extract_keys", return_value=[mock_key]):
                with patch.object(coordinator, "_check_balances", new_callable=AsyncMock, return_value=[]):
                    result = await coordinator.run_once()
        assert result.raw_leaks_fetched == 1
        assert result.keys_extracted == 1

    @pytest.mark.asyncio
    async def test_deduplication(self, mock_key):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=["github"])
        raw_leaks = [RawLeak(text="t1", source_name="github"), RawLeak(text="t2", source_name="github")]
        with patch.object(coordinator, "_fetch_all_sources", new_callable=AsyncMock, return_value=raw_leaks):
            with patch("src.modules.crypto.leak_finder.coordinator.extract_keys", return_value=[mock_key]):
                with patch.object(coordinator, "_check_balances", new_callable=AsyncMock, return_value=[]):
                    result = await coordinator.run_once()
        assert result.keys_deduplicated == 1

    @pytest.mark.asyncio
    async def test_search_address(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=["github"])
        mock_leaks = [RawLeak(text="found", source_name="github")]
        with patch("src.modules.crypto.leak_finder.coordinator.extract_keys", return_value=[]):
            with patch.object(coordinator, "_create_source") as mock_create:
                mock_source = AsyncMock()
                mock_source.search_for_address = AsyncMock(return_value=mock_leaks)
                mock_create.return_value = mock_source
                result = await coordinator.search_address("0xTest")
        assert result.raw_leaks_fetched >= 1

    @pytest.mark.asyncio
    async def test_start_stop(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=[])
        with patch("src.modules.crypto.leak_finder.coordinator.ScannerCoordinator") as MockCoord:
            MockCoord.return_value = AsyncMock()
            with patch("src.modules.crypto.leak_finder.coordinator.HitLogger") as MockLogger:
                MockLogger.return_value = AsyncMock()
                await coordinator.start()
                assert coordinator._running is True
                await coordinator.stop()
                assert coordinator._running is False

    def test_create_source_github(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        assert isinstance(LeakFinderCoordinator()._create_source("github"), GitHubLeakSource)

    def test_create_source_unknown(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        assert LeakFinderCoordinator()._create_source("nonexistent") is None

    def test_find_chain(self):
        from src.modules.crypto.balance.chains import chain_by_name
        assert chain_by_name("Ethereum") is not None
        assert chain_by_name("ETH") is not None
        assert chain_by_name("Solana") is not None
        assert chain_by_name("Nonexistent") is None

    @pytest.mark.asyncio
    async def test_fetch_all_sources_parallel(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=["github", "paste"])
        mock_leaks_1 = [RawLeak(text="from github", source_name="github")]
        mock_leaks_2 = [RawLeak(text="from paste", source_name="paste")]
        async def mock_fetch_github():
            return mock_leaks_1
        async def mock_fetch_paste():
            return mock_leaks_2
        with patch.object(coordinator, "_create_source") as mock_create:
            mock_github = AsyncMock()
            mock_github.fetch_raw_leaks = mock_fetch_github
            mock_paste = AsyncMock()
            mock_paste.fetch_raw_leaks = mock_fetch_paste
            mock_create.side_effect = lambda name: mock_github if name == "github" else mock_paste
            leaks = await coordinator._fetch_all_sources()
        assert len(leaks) == 2

    @pytest.mark.asyncio
    async def test_source_error_handled_gracefully(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator
        coordinator = LeakFinderCoordinator(sources=["github"])
        with patch.object(coordinator, "_create_source") as mock_create:
            mock_source = AsyncMock()
            mock_source.fetch_raw_leaks = AsyncMock(side_effect=RuntimeError("API down"))
            mock_create.return_value = mock_source
            leaks = await coordinator._fetch_all_sources()
        assert leaks == []
