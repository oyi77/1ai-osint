"""Tests for all 8 leak_finder source adapters."""
import asyncio
import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.modules.sources.github_source import RawLeak


# ---------------------------------------------------------------------------
# GitHubLeakSource
# ---------------------------------------------------------------------------
class TestGitHubLeakSource:
    def _make_source(self):
        from src.modules.sources.github_source import GitHubLeakSource
        return GitHubLeakSource(github_token="ghp_test", rate_limit=100, timeout=5.0)

    def _mock_client(self, responses):
        """Return a mock AsyncClient that yields responses in order."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.raise_for_status = MagicMock()
        search_resp.json.return_value = {
            "items": [{"html_url": "https://github.com/user/repo/blob/main/.env"}]
        }
        raw_resp = MagicMock()
        raw_resp.text = "PRIVATE_KEY=abcdef1234567890"
        raw_resp.raise_for_status = MagicMock()
        # third call for gist listing
        gist_resp = MagicMock()
        gist_resp.status_code = 200
        gist_resp.json.return_value = []
        mock_client = self._mock_client([search_resp, raw_resp, gist_resp])
        with patch("src.modules.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(queries=["test query"], max_per_query=1)
        assert len(leaks) == 1
        assert leaks[0].source_name == "github"
        assert "PRIVATE_KEY" in leaks[0].text

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty_results(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.raise_for_status = MagicMock()
        search_resp.json.return_value = {"items": []}
        gist_resp = MagicMock()
        gist_resp.status_code = 200
        gist_resp.json.return_value = []
        mock_client = self._mock_client([search_resp, gist_resp])
        with patch("src.modules.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(queries=["no results"], max_per_query=1)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.raise_for_status = MagicMock(side_effect=Exception("Server Error"))
        gist_resp = MagicMock()
        gist_resp.status_code = 200
        gist_resp.json.return_value = []
        mock_client = self._mock_client([error_resp, gist_resp])
        with patch("src.modules.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(queries=["error query"], max_per_query=1)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        source = self._make_source()
        import httpx as _httpx
        mock_client = self._mock_client([_httpx.TimeoutException("timed out")])
        gist_resp = MagicMock()
        gist_resp.status_code = 200
        gist_resp.json.return_value = []
        mock_client.get = AsyncMock(side_effect=[_httpx.TimeoutException("timed out"), gist_resp])
        with patch("src.modules.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(queries=["timeout"], max_per_query=1)
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.raise_for_status = MagicMock()
        search_resp.json.return_value = {"items": []}
        gist_resp = MagicMock()
        gist_resp.status_code = 200
        gist_resp.json.return_value = []
        mock_client = self._mock_client([search_resp, gist_resp])
        with patch("src.modules.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.search_for_address("0xabcdef")
        assert isinstance(leaks, list)

    def test_make_headers_with_token(self):
        source = self._make_source()
        h = source._make_headers()
        assert h["Authorization"] == "token ghp_test"

    def test_make_headers_without_token(self):
        from src.modules.sources.github_source import GitHubLeakSource
        h = GitHubLeakSource()._make_headers()
        assert "Authorization" not in h

    @pytest.mark.asyncio
    async def test_rate_limit_backoff_on_403(self):
        source = self._make_source()
        resp_403 = MagicMock()
        resp_403.status_code = 403
        resp_403.raise_for_status = MagicMock()
        gist_resp = MagicMock()
        gist_resp.status_code = 200
        gist_resp.json.return_value = []
        mock_client = self._mock_client([resp_403, gist_resp])
        with patch("src.modules.sources.github_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.github_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(queries=["rate limit"], max_per_query=1)
        assert leaks == []


# ---------------------------------------------------------------------------
# RedditSource
# ---------------------------------------------------------------------------
class TestRedditSource:
    def _make_source(self):
        from src.modules.sources.reddit_source import RedditSource
        return RedditSource(max_per_sub=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {
            "data": [
                {"permalink": "/r/test/comments/abc", "title": "Leaked key", "selftext": "0xabcdef"},
            ]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=ok_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.reddit_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.reddit_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert any(leak.source_name == "reddit" for leak in leaks)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {"data": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=ok_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.reddit_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.reddit_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 429
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.reddit_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.reddit_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        import httpx as _httpx
        source = self._make_source()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=_httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.reddit_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.reddit_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {
            "data": [
                {"permalink": "/r/test/comments/abc", "title": "Found", "selftext": "addr_0x1234"},
            ]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=ok_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.reddit_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.reddit_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.search_for_address("addr_0x1234")
        assert len(leaks) == 1


# ---------------------------------------------------------------------------
# BitcoinTalkSource
# ---------------------------------------------------------------------------
class TestBitcoinTalkSource:
    def _make_source(self):
        from src.modules.sources.bitcointalk_source import BitcoinTalkSource
        return BitcoinTalkSource(max_topics=1, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        board_html = '<a href="http://bitcointalk.org/index.php?topic=123.0">Topic</a>'
        board_resp = MagicMock()
        board_resp.status_code = 200
        board_resp.text = board_html
        topic_html = '<div class="post">I found a private key abc123 in a wallet</div>'
        topic_resp = MagicMock()
        topic_resp.status_code = 200
        topic_resp.text = topic_html
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[board_resp, topic_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.bitcointalk_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.bitcointalk_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "bitcointalk"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        empty_board = MagicMock()
        empty_board.status_code = 200
        empty_board.text = "<html><body>No topics</body></html>"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=empty_board)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.bitcointalk_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.bitcointalk_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 403
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.bitcointalk_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.bitcointalk_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        import httpx as _httpx
        source = self._make_source()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=_httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.bitcointalk_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.bitcointalk_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []


# ---------------------------------------------------------------------------
# PasteSource
# ---------------------------------------------------------------------------
class TestPasteSource:
    def _make_source(self):
        from src.modules.sources.paste_source import PasteSource
        return PasteSource(max_pastes_per_source=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        archive_resp = MagicMock()
        archive_resp.status_code = 200
        archive_resp.text = '<a href="/abc123DEF">Paste 1</a>'
        archive_resp.raise_for_status = MagicMock()
        raw_resp = MagicMock()
        raw_resp.status_code = 200
        raw_resp.text = "PRIVATE_KEY=deadbeef"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[archive_resp, raw_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.paste_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.paste_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        empty_resp = MagicMock()
        empty_resp.status_code = 200
        empty_resp.text = "<html>No pastes</html>"
        empty_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=empty_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.paste_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.paste_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 500
        err_resp.raise_for_status = MagicMock(side_effect=Exception("Server Error"))
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.paste_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.paste_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        import httpx as _httpx
        source = self._make_source()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=_httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.paste_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.paste_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    def test_parse_pastebin_ids(self):
        from src.modules.sources.paste_source import PasteSource
        html = '<a href="/abc123DEF">Paste 1</a><a href="/archive">Archive</a><a href="/login">Login</a>'
        ids = PasteSource._parse_pastebin_ids(html)
        assert "abc123DEF" in ids
        assert "archive" not in ids
        assert "login" not in ids

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        mock_leaks = [
            RawLeak(text="leaked key 0xABCDEF1234", source_name="pastebin", source_url="https://pastebin.com/test123"),
            RawLeak(text="nothing here", source_name="pastebin", source_url="https://pastebin.com/test456"),
        ]
        with patch.object(source, "fetch_raw_leaks", new_callable=AsyncMock, return_value=mock_leaks):
            leaks = await source.search_for_address("0xABCDEF1234")
        assert len(leaks) == 1
        assert "0xABCDEF1234" in leaks[0].text


# ---------------------------------------------------------------------------
# TwitterSource
# ---------------------------------------------------------------------------
class TestTwitterSource:
    def _make_source(self):
        from src.modules.sources.twitter_source import TwitterSource
        return TwitterSource(max_per_query=5, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        source._cli_path = "/usr/bin/twitter"
        tweet_data = [
            {"id": "1", "text": "found a seed phrase", "author": {"screen_name": "user1"}},
        ]
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(
            __import__("json").dumps(tweet_data).encode(), b""
        ))
        with patch("src.modules.sources.twitter_source.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("src.modules.sources.twitter_source.asyncio.wait_for", new_callable=AsyncMock, return_value=(json.dumps(tweet_data).encode(), b"")):
                leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "twitter"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_no_cli(self):
        from src.modules.sources.twitter_source import TwitterSource
        source = TwitterSource()
        source._cli_path = None
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_cli_error(self):
        source = self._make_source()
        source._cli_path = "/usr/bin/twitter"
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
        with patch("src.modules.sources.twitter_source.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("src.modules.sources.twitter_source.asyncio.wait_for", new_callable=AsyncMock, return_value=(b"", b"error")):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        source = self._make_source()
        source._cli_path = "/usr/bin/twitter"
        with patch("src.modules.sources.twitter_source.asyncio.create_subprocess_exec", return_value=AsyncMock()):
            with patch("src.modules.sources.twitter_source.asyncio.wait_for", new_callable=AsyncMock, side_effect=asyncio.TimeoutError):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_cli(self):
        from src.modules.sources.twitter_source import TwitterSource
        source = TwitterSource()
        source._cli_path = None
        leaks = await source.search_for_address("0x1234")
        assert leaks == []


# ---------------------------------------------------------------------------
# TelegramSource
# ---------------------------------------------------------------------------
class TestTelegramSource:
    def _make_source(self):
        from src.modules.sources.telegram_source import TelegramSource
        return TelegramSource(api_id=12345, api_hash="abc123", max_messages_per_channel=5, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_no_telethon(self):
        source = self._make_source()
        with patch.dict("sys.modules", {"telethon": None}):
            leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_no_credentials(self):
        from src.modules.sources.telegram_source import TelegramSource
        source = TelegramSource(api_id=0, api_hash="")
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_connection_failure(self):
        source = self._make_source()
        mock_telethon = MagicMock()
        mock_client = AsyncMock()
        mock_client.start = AsyncMock(side_effect=Exception("Connection failed"))
        mock_client.disconnect = AsyncMock()
        mock_telethon.TelegramClient = MagicMock(return_value=mock_client)
        with patch.dict("sys.modules", {"telethon": mock_telethon, "telethon.tl.functions.contacts": MagicMock()}):
            with patch("src.modules.sources.telegram_source.asyncio.wait_for", new_callable=AsyncMock, side_effect=Exception("Connection failed")):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    def test_extract_flood_wait(self):
        from src.modules.sources.telegram_source import TelegramSource
        assert TelegramSource._extract_flood_wait("A wait of 30 seconds is required") == 30
        assert TelegramSource._extract_flood_wait("Please wait 45 more") == 45
        assert TelegramSource._extract_flood_wait("unknown error") == 60

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        mock_msg = MagicMock()
        mock_msg.text = "private key 0xabcdef1234567890abcdef1234567890abcdef12"
        mock_msg.id = 1

        mock_entity = MagicMock()

        async def mock_iter_messages(entity, limit=100):
            yield mock_msg

        mock_telethon = MagicMock()
        mock_client = AsyncMock()
        mock_client.start = AsyncMock()
        mock_client.disconnect = AsyncMock()
        mock_client.get_entity = AsyncMock(return_value=mock_entity)
        mock_client.iter_messages = mock_iter_messages

        search_result = MagicMock()
        search_result.chats = []
        mock_client.__call__ = AsyncMock(return_value=search_result)
        mock_telethon.TelegramClient = MagicMock(return_value=mock_client)

        contacts_mod = MagicMock()
        contacts_mod.SearchRequest = MagicMock(return_value=search_result)

        with patch.dict("sys.modules", {"telethon": mock_telethon, "telethon.tl.functions.contacts": contacts_mod}):
            with patch("src.modules.sources.telegram_source.asyncio.wait_for", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks(keywords=["test"])
        # Channels list is empty so no messages iterated
        assert isinstance(leaks, list)


# ---------------------------------------------------------------------------
# DuckDuckGoSource
# ---------------------------------------------------------------------------
class TestDuckDuckGoSource:
    def _make_source(self):
        from src.modules.sources.duckduckgo_source import DuckDuckGoSource
        return DuckDuckGoSource(max_per_query=3, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.text = 'href="https://example.com/leak.txt"'
        page_resp = MagicMock()
        page_resp.status_code = 200
        page_resp.text = "A" * 100
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=search_resp)
        mock_client.get = AsyncMock(return_value=page_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.duckduckgo_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.duckduckgo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.duckduckgo_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "duckduckgo"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.text = "no results"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=search_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.duckduckgo_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.duckduckgo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.duckduckgo_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 429
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.duckduckgo_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.duckduckgo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.duckduckgo_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        import httpx as _httpx
        source = self._make_source()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=_httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.duckduckgo_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.duckduckgo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.duckduckgo_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []


# ---------------------------------------------------------------------------
# GitLabSource
# ---------------------------------------------------------------------------
class TestGitLabSource:
    def _make_source(self):
        from src.modules.sources.gitlab_source import GitLabSource
        return GitLabSource(max_per_query=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = [{"project_id": 1, "data": "PRIVATE_KEY=abcdef"}]
        snippet_list_resp = MagicMock()
        snippet_list_resp.status_code = 200
        snippet_list_resp.json.return_value = []
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[search_resp, snippet_list_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.gitlab_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.gitlab_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "gitlab"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        empty_resp = MagicMock()
        empty_resp.status_code = 200
        empty_resp.json.return_value = []
        snippet_resp = MagicMock()
        snippet_resp.status_code = 200
        snippet_resp.json.return_value = []
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[empty_resp, snippet_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.gitlab_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.gitlab_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 403
        snippet_resp = MagicMock()
        snippet_resp.status_code = 403
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[err_resp, snippet_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.gitlab_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.gitlab_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_timeout(self):
        import httpx as _httpx
        source = self._make_source()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=_httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.gitlab_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.gitlab_source.asyncio.sleep", new_callable=AsyncMock):
                leaks = await source.fetch_raw_leaks()
        assert leaks == []


# ---------------------------------------------------------------------------
# NpmSource
# ---------------------------------------------------------------------------
class TestNpmSource:
    def _make_source(self):
        from src.modules.sources.npm_source import NpmSource
        return NpmSource(max_per_query=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = {
            "objects": [{"package": {"name": "test-pkg"}}]
        }
        pkg_resp = MagicMock()
        pkg_resp.status_code = 200
        pkg_resp.json.return_value = {
            "readme": "PRIVATE_KEY=abcdef1234567890",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"scripts": {}}},
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[search_resp, pkg_resp, search_resp, pkg_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.npm_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.npm_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.npm_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert any(leak.source_name == "npm_readme" for leak in leaks)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 500
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.npm_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.npm_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.npm_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = {"objects": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=search_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.npm_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.npm_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.npm_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("0x123")
        assert leaks == []


# ---------------------------------------------------------------------------
# StackOverflowSource
# ---------------------------------------------------------------------------
class TestStackOverflowSource:
    def _make_source(self):
        from src.modules.sources.stackoverflow_source import StackOverflowSource
        return StackOverflowSource(max_per_query=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "items": [{
                "question_id": 1,
                "title": "How to store private key",
                "body": "<p>PRIVATE_KEY=abcdef</p>",
                "link": "https://stackoverflow.com/q/1",
            }]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.stackoverflow_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.stackoverflow_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.stackoverflow_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "stackoverflow"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 400
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.stackoverflow_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.stackoverflow_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.stackoverflow_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"items": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.stackoverflow_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.stackoverflow_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.stackoverflow_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("0x123")
        assert leaks == []


# ---------------------------------------------------------------------------
# CodebergSource
# ---------------------------------------------------------------------------
class TestCodebergSource:
    def _make_source(self):
        from src.modules.sources.codeberg_source import CodebergSource
        return CodebergSource(max_per_query=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = {"data": [{"full_name": "user/repo"}]}
        file_resp = MagicMock()
        file_resp.status_code = 200
        file_resp.json.return_value = {"content": "UFJJVkFURV9LRVk9YWJjZA==", "encoding": "base64"}
        readme_resp = MagicMock()
        readme_resp.status_code = 200
        readme_resp.json.return_value = {"content": "# Test", "encoding": "utf-8"}
        empty_resp = MagicMock()
        empty_resp.status_code = 404
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[
            search_resp, file_resp, empty_resp, empty_resp, empty_resp,
            empty_resp, empty_resp, readme_resp,
        ])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.codeberg_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.codeberg_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.codeberg_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_api_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 500
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.codeberg_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.codeberg_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.codeberg_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = {"data": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=search_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.codeberg_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.codeberg_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.codeberg_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("0x123")
        assert leaks == []


# ---------------------------------------------------------------------------
# ChiasmodonBridge
# ---------------------------------------------------------------------------
class TestChiasmodonBridge:
    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        from src.modules.sources.chiasmodon_bridge import ChiasmodonBridge
        mock_tool = MagicMock()
        mock_tool.search.return_value = {
            "status": "ok",
            "result": [{"email": "test@example.com", "password": "secret"}],
        }
        bridge = ChiasmodonBridge("hibp", mock_tool)
        leaks = await bridge.fetch_raw_leaks("test")
        assert len(leaks) == 1
        assert leaks[0].source_name == "chiasmodon_hibp"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_error_status(self):
        from src.modules.sources.chiasmodon_bridge import ChiasmodonBridge
        mock_tool = MagicMock()
        mock_tool.search.return_value = {"status": "error", "error": "API down"}
        bridge = ChiasmodonBridge("scylla", mock_tool)
        leaks = await bridge.fetch_raw_leaks("test")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_exception(self):
        from src.modules.sources.chiasmodon_bridge import ChiasmodonBridge
        mock_tool = MagicMock()
        mock_tool.search.side_effect = Exception("connection failed")
        bridge = ChiasmodonBridge("shodan", mock_tool)
        leaks = await bridge.fetch_raw_leaks("test")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        from src.modules.sources.chiasmodon_bridge import ChiasmodonBridge
        mock_tool = MagicMock()
        mock_tool.search.return_value = {"status": "ok", "result": []}
        bridge = ChiasmodonBridge("intelx", mock_tool)
        leaks = await bridge.search_for_address("0x123")
        assert leaks == []

    def test_get_chiasmodon_sources(self):
        from src.modules.sources.chiasmodon_bridge import get_chiasmodon_sources
        sources = get_chiasmodon_sources()
        assert isinstance(sources, dict)

    def test_load_chiasmodon_tool_unknown(self):
        from src.modules.sources.chiasmodon_bridge import _load_chiasmodon_tool
        result = _load_chiasmodon_tool("nonexistent_source")
        assert result is None


# ---------------------------------------------------------------------------
# WaybackSource
# ---------------------------------------------------------------------------
class TestWaybackSource:
    def _make_source(self):
        from src.modules.sources.wayback_source import WaybackSource
        return WaybackSource(max_per_query=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        cdx_resp = MagicMock()
        cdx_resp.status_code = 200
        cdx_resp.json.return_value = [
            ["original", "timestamp", "statuscode"],
            ["https://example.com/.env", "20240101", "200"],
        ]
        page_resp = MagicMock()
        page_resp.status_code = 200
        page_resp.text = "PRIVATE_KEY=abcdef1234567890"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[cdx_resp, page_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.wayback_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.wayback_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.wayback_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "wayback"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        cdx_resp = MagicMock()
        cdx_resp.status_code = 200
        cdx_resp.json.return_value = [["original", "timestamp", "statuscode"]]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=cdx_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.wayback_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.wayback_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.wayback_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        cdx_resp = MagicMock()
        cdx_resp.status_code = 200
        cdx_resp.json.return_value = [["original", "timestamp", "statuscode"]]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=cdx_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.wayback_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.wayback_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.wayback_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("0x123")
        assert leaks == []


# ---------------------------------------------------------------------------
# CrtShSource
# ---------------------------------------------------------------------------
class TestCrtShSource:
    def _make_source(self):
        from src.modules.sources.crtsh_source import CrtShSource
        return CrtShSource(max_results=5, request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"id": 1, "name_value": "example.com"}]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.crtsh_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.crtsh_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.crtsh_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) == 1
        assert leaks[0].source_name == "crtsh"

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_error(self):
        source = self._make_source()
        err_resp = MagicMock()
        err_resp.status_code = 500
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=err_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.crtsh_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.crtsh_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.crtsh_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"id": 1, "name_value": "test.com"}]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.crtsh_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.crtsh_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.crtsh_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test.com")
        assert len(leaks) == 1


# ---------------------------------------------------------------------------
# VirusTotalSource
# ---------------------------------------------------------------------------
class TestVirusTotalSource:
    def _make_source(self):
        from src.modules.sources.virustotal_source import VirusTotalSource
        return VirusTotalSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_no_key(self):
        from src.modules.sources.virustotal_source import VirusTotalSource
        source = VirusTotalSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": [{"attributes": {"url": "https://example.com", "tags": ["crypto"]}}]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.virustotal_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.virustotal_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.virustotal_source.time.monotonic", return_value=0.0):
                    leaks = await source.fetch_raw_leaks()
        assert len(leaks) >= 1
        assert leaks[0].source_name == "virustotal"

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.virustotal_source import VirusTotalSource
        source = VirusTotalSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {"attributes": {"reputation": 0, "tags": ["clean"]}}
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.virustotal_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.virustotal_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.virustotal_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 1


# ---------------------------------------------------------------------------
# SherlockSource
# ---------------------------------------------------------------------------
class TestSherlockSource:
    def _make_source(self):
        from src.modules.sources.sherlock_source import SherlockSource
        return SherlockSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.sherlock_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("testuser")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(
            b'{"GitHub": {"status": "Claimed", "url": "https://github.com/testuser"}}',
            b"",
        ))
        with patch("src.modules.sources.sherlock_source.shutil.which", return_value="/usr/bin/sherlock"):
            with patch("src.modules.sources.sherlock_source.asyncio.create_subprocess_exec", return_value=mock_proc):
                leaks = await source.search_for_address("testuser")
        assert len(leaks) == 1
        assert "GitHub" in leaks[0].text


# ---------------------------------------------------------------------------
# HoleheSource
# ---------------------------------------------------------------------------
class TestHoleheSource:
    def _make_source(self):
        from src.modules.sources.holehe_source import HoleheSource
        return HoleheSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_at(self):
        source = self._make_source()
        leaks = await source.search_for_address("notanemail")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_import_error(self):
        source = self._make_source()
        with patch.dict("sys.modules", {"holehe": None}):
            leaks = await source.search_for_address("test@example.com")
        assert leaks == []


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MaigretSource
# ---------------------------------------------------------------------------
class TestMaigretSource:
    def _make_source(self):
        from src.modules.sources.maigret_source import MaigretSource
        return MaigretSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.maigret_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("testuser")
        assert leaks == []


# ---------------------------------------------------------------------------
# TheHarvesterSource
# ---------------------------------------------------------------------------
class TestTheHarvesterSource:
    def _make_source(self):
        from src.modules.sources.theharvester_source import TheHarvesterSource
        return TheHarvesterSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.theharvester_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# AmassSource
# ---------------------------------------------------------------------------
class TestAmassSource:
    def _make_source(self):
        from src.modules.sources.amass_source import AmassSource
        return AmassSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.amass_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# WhatsMyNameSource
# ---------------------------------------------------------------------------
class TestWhatsMyNameSource:
    def _make_source(self):
        from src.modules.sources.whatsmyname_source import WhatsMyNameSource
        return WhatsMyNameSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Results for testuser"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.whatsmyname_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.whatsmyname_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.whatsmyname_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("testuser")
        assert len(leaks) == 1
        assert leaks[0].source_name == "whatsmyname"


# ---------------------------------------------------------------------------
# WhoisSource
# ---------------------------------------------------------------------------
class TestWhoisSource:
    def _make_source(self):
        from src.modules.sources.whois_source import WhoisSource
        return WhoisSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"name": "NET-8-8-8-0", "startAddress": "8.8.8.0"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.whois_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.whois_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.whois_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("8.8.8.8")
        assert len(leaks) == 1
        assert leaks[0].source_name == "whois"


# ---------------------------------------------------------------------------
# DNSDumpsterSource
# ---------------------------------------------------------------------------
class TestDNSDumpsterSource:
    def _make_source(self):
        from src.modules.sources.dnsdumpster_source import DNSDumpsterSource
        return DNSDumpsterSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []


# ---------------------------------------------------------------------------
# SecurityTrailsSource
# ---------------------------------------------------------------------------
class TestSecurityTrailsSource:
    def _make_source(self):
        from src.modules.sources.securitytrails_source import SecurityTrailsSource
        return SecurityTrailsSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.securitytrails_source import SecurityTrailsSource
        source = SecurityTrailsSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        sub_resp = MagicMock()
        sub_resp.status_code = 200
        sub_resp.json.return_value = {"subdomains": ["www", "mail"]}
        dns_resp = MagicMock()
        dns_resp.status_code = 200
        dns_resp.json.return_value = {"hostname": "example.com"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[sub_resp, dns_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.securitytrails_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.securitytrails_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.securitytrails_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 2


# ---------------------------------------------------------------------------
# HunterSource
# ---------------------------------------------------------------------------
class TestHunterSource:
    def _make_source(self):
        from src.modules.sources.hunter_source import HunterSource
        return HunterSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.hunter_source import HunterSource
        source = HunterSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": {"emails": [{"value": "test@example.com"}]}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.hunter_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.hunter_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.hunter_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "hunter"


# ---------------------------------------------------------------------------
# PhoneInfogaSource
# ---------------------------------------------------------------------------
class TestPhoneInfogaSource:
    def _make_source(self):
        from src.modules.sources.phoneinfoga_source import PhoneInfogaSource
        return PhoneInfogaSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.phoneinfoga_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("+1234567890")
        assert leaks == []


# ---------------------------------------------------------------------------
# Additional sources (autoresearch-added)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# DNSDumpsterSource (additional tests)
# ---------------------------------------------------------------------------
class TestDNSDumpsterSourceExtra:
    def _make_source(self):
        from src.modules.sources.dnsdumpster_source import DNSDumpsterSource
        return DNSDumpsterSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        get_resp = MagicMock()
        get_resp.status_code = 200
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "<html>example.com results</html>"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = AsyncMock(return_value=post_resp)
        mock_client.cookies = MagicMock()
        cookie = MagicMock()
        cookie.name = "csrftoken"
        cookie.value = "tok123"
        mock_client.cookies.jar = [cookie]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.dnsdumpster_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.dnsdumpster_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.dnsdumpster_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "dnsdumpster"

    @pytest.mark.asyncio
    async def test_search_for_address_no_csrf(self):
        source = self._make_source()
        get_resp = MagicMock()
        get_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.cookies = MagicMock()
        mock_client.cookies.jar = []
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.dnsdumpster_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.dnsdumpster_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.dnsdumpster_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_error(self):
        source = self._make_source()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("network error"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.dnsdumpster_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.dnsdumpster_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.dnsdumpster_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# Subprocess-based sources (mock binary tests)
# ---------------------------------------------------------------------------
class TestMaigretSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.maigret_source import MaigretSource
        source = MaigretSource(timeout=5.0)
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(
            b'{"GitHub": {"url_user": "https://github.com/test", "status": "Claimed"}}',
            b"",
        ))
        with patch("src.modules.sources.maigret_source.shutil.which", return_value="/usr/bin/maigret"):
            with patch("src.modules.sources.maigret_source.asyncio.create_subprocess_exec", return_value=mock_proc):
                leaks = await source.search_for_address("testuser")
        assert len(leaks) >= 1
        assert leaks[0].source_name == "maigret"


class TestAmassSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.amass_source import AmassSource
        source = AmassSource(timeout=5.0)
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(
            b"sub1.example.com\nsub2.example.com",
            b"",
        ))
        with patch("src.modules.sources.amass_source.shutil.which", return_value="/usr/bin/amass"):
            with patch("src.modules.sources.amass_source.asyncio.create_subprocess_exec", return_value=mock_proc):
                leaks = await source.search_for_address("example.com")
        assert len(leaks) >= 1
        assert leaks[0].source_name == "amass"




# ---------------------------------------------------------------------------
# H8mailSource
# ---------------------------------------------------------------------------
class TestH8mailSource:
    def _make_source(self):
        from src.modules.sources.h8mail_source import H8mailSource
        return H8mailSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_email(self):
        source = self._make_source()
        leaks = await source.search_for_address("notanemail")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.h8mail_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("test@example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# ExiftoolSource
# ---------------------------------------------------------------------------
class TestExiftoolSource:
    def _make_source(self):
        from src.modules.sources.exiftool_source import ExiftoolSource
        return ExiftoolSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.exiftool_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("/path/to/file.jpg")
        assert leaks == []


# ---------------------------------------------------------------------------
# SocialSource
# ---------------------------------------------------------------------------
class TestSocialSource:
    def _make_source(self):
        from src.modules.sources.social_source import SocialSource
        return SocialSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"login": "testuser", "id": 12345}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.social_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.social_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.social_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("testuser")
        assert len(leaks) >= 1


# ---------------------------------------------------------------------------
# IntelxSource
# ---------------------------------------------------------------------------
class TestIntelxSource:
    def _make_source(self):
        from src.modules.sources.intelx_source import IntelxSource
        return IntelxSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.intelx_source import IntelxSource
        source = IntelxSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("test@example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# LeakcheckSource
# ---------------------------------------------------------------------------
class TestLeakcheckSource:
    def _make_source(self):
        from src.modules.sources.leakcheck_source import LeakcheckSource
        return LeakcheckSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.leakcheck_source import LeakcheckSource
        source = LeakcheckSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("test@example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# Additional subprocess sources
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# IntelxSource (additional)
# ---------------------------------------------------------------------------
class TestIntelxSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.intelx_source import IntelxSource
        source = IntelxSource(api_key="test_key", request_delay=0.0, timeout=5.0)
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = {"id": "abc123"}
        result_resp = MagicMock()
        result_resp.status_code = 200
        result_resp.json.return_value = {"records": [{"value": "test@example.com"}]}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=search_resp)
        mock_client.get = AsyncMock(return_value=result_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.intelx_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.intelx_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.intelx_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "intelx"


# ---------------------------------------------------------------------------
# LeakcheckSource (additional)
# ---------------------------------------------------------------------------
class TestLeakcheckSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.leakcheck_source import LeakcheckSource
        source = LeakcheckSource(api_key="test_key", request_delay=0.0, timeout=5.0)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"found": 2, "sources": [{"name": "breach1"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.leakcheck_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.leakcheck_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.leakcheck_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "leakcheck"


# ---------------------------------------------------------------------------
# H8mailSource (additional)
# ---------------------------------------------------------------------------
class TestH8mailSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.h8mail_source import H8mailSource
        source = H8mailSource(timeout=5.0)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b'[{"email": "test@example.com", "password": "secret"}]', b""))
        with patch("src.modules.sources.h8mail_source.shutil.which", return_value="/usr/bin/h8mail"):
            with patch("src.modules.sources.h8mail_source.asyncio.create_subprocess_exec", return_value=mock_proc):
                with patch("src.modules.sources.h8mail_source.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
                    mock_wait.return_value = (b'[{"email": "test@example.com", "password": "secret"}]', b"")
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "h8mail"


# ---------------------------------------------------------------------------
# ExiftoolSource (additional)
# ---------------------------------------------------------------------------
class TestExiftoolSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.exiftool_source import ExiftoolSource
        source = ExiftoolSource(timeout=5.0)
        with patch("src.modules.sources.exiftool_source.shutil.which", return_value="/usr/bin/exiftool"):
            with patch("src.modules.sources.exiftool_source.asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = MagicMock()
                mock_proc.communicate = AsyncMock(return_value=(b'[{"SourceFile": "test.jpg", "GPS": "lat,lon"}]', b""))
                mock_exec.return_value = mock_proc
                with patch("src.modules.sources.exiftool_source.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
                    mock_wait.return_value = (b'[{"SourceFile": "test.jpg", "GPS": "lat,lon"}]', b"")
                    leaks = await source.search_for_address("/path/to/file.jpg")
        assert len(leaks) == 1
        assert leaks[0].source_name == "exiftool"


# ---------------------------------------------------------------------------
# PhoneInfogaSource (additional)
# ---------------------------------------------------------------------------
class TestPhoneInfogaSourceFull:
    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        from src.modules.sources.phoneinfoga_source import PhoneInfogaSource
        source = PhoneInfogaSource(timeout=5.0)
        with patch("src.modules.sources.phoneinfoga_source.shutil.which", return_value="/usr/bin/phoneinfoga"):
            with patch("src.modules.sources.phoneinfoga_source.asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = MagicMock()
                mock_proc.communicate = AsyncMock(return_value=(b'{"valid": true, "country": "US"}', b""))
                mock_exec.return_value = mock_proc
                with patch("src.modules.sources.phoneinfoga_source.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
                    mock_wait.return_value = (b'{"valid": true, "country": "US"}', b"")
                    leaks = await source.search_for_address("+1234567890")
        assert len(leaks) == 1
        assert leaks[0].source_name == "phoneinfoga"


class TestTheHarvesterSourceFull2:
    @pytest.mark.asyncio
    async def test_search_for_address_timeout(self):
        from src.modules.sources.theharvester_source import TheHarvesterSource
        source = TheHarvesterSource(timeout=0.1)
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        with patch("src.modules.sources.theharvester_source.shutil.which", return_value="/usr/bin/theHarvester"):
            with patch("src.modules.sources.theharvester_source.asyncio.create_subprocess_exec", return_value=mock_proc):
                leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_exception(self):
        from src.modules.sources.theharvester_source import TheHarvesterSource
        source = TheHarvesterSource(timeout=5.0)
        with patch("src.modules.sources.theharvester_source.shutil.which", return_value="/usr/bin/theHarvester"):
            with patch("src.modules.sources.theharvester_source.asyncio.create_subprocess_exec", side_effect=Exception("fail")):
                leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# DehashedSource
# ---------------------------------------------------------------------------
class TestDehashedSource:
    def _make_source(self):
        from src.modules.sources.dehashed_source import DehashedSource
        return DehashedSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.dehashed_source import DehashedSource
        source = DehashedSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("test@example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"entries": [{"email": "test@example.com", "password": "secret"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.dehashed_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.dehashed_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.dehashed_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "dehashed"


# ---------------------------------------------------------------------------
# SnyllaSource
# ---------------------------------------------------------------------------
class TestSnyllaSource:
    def _make_source(self):
        from src.modules.sources.snylla_source import ScyllaSource
        return ScyllaSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.snylla_source import ScyllaSource
        source = ScyllaSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("test@example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"email": "test@example.com", "password": "secret"}]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.snylla_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.snylla_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.snylla_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "scylla"


# ---------------------------------------------------------------------------
# SnusbaseSource
# ---------------------------------------------------------------------------
class TestSnusbaseSource:
    def _make_source(self):
        from src.modules.sources.snusbase_source import SnusbaseSource
        return SnusbaseSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.snusbase_source import SnusbaseSource
        source = SnusbaseSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("test@example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"result": {"users": [{"email": "test@example.com"}]}}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.snusbase_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.snusbase_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.snusbase_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "snusbase"


# ---------------------------------------------------------------------------
# HIBPSource
# ---------------------------------------------------------------------------
class TestHIBPSource:
    def _make_source(self):
        from src.modules.sources.hibp_source import HIBPSource
        return HIBPSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.hibp_source import HIBPSource
        source = HIBPSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("test@example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_email(self):
        source = self._make_source()
        leaks = await source.search_for_address("notanemail")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [{"Name": "LinkedIn", "BreachDate": "2012-05-05", "DataClasses": ["Email", "Password"]}]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.hibp_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.hibp_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.hibp_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("test@example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "hibp"

    @pytest.mark.asyncio
    async def test_search_for_address_not_found(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 404
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.hibp_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.hibp_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.hibp_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("clean@example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# SpiderFootSource
# ---------------------------------------------------------------------------
class TestSpiderFootSource:
    def _make_source(self):
        from src.modules.sources.spiderfoot_source import SpiderFootSource
        return SpiderFootSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.spiderfoot_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        with patch("src.modules.sources.spiderfoot_source.shutil.which", return_value="/usr/bin/spiderfoot"):
            with patch("src.modules.sources.spiderfoot_source.asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = MagicMock()
                mock_proc.communicate = AsyncMock(return_value=(b'[{"element": "example.com", "type": "domain"}]', b""))
                mock_exec.return_value = mock_proc
                with patch("src.modules.sources.spiderfoot_source.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
                    mock_wait.return_value = (b'[{"element": "example.com", "type": "domain"}]', b"")
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "spiderfoot"


# ---------------------------------------------------------------------------
# ShodanSource
# ---------------------------------------------------------------------------
class TestShodanSource:
    def _make_source(self):
        from src.modules.sources.shodan_source import ShodanSource
        return ShodanSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.shodan_source import ShodanSource
        source = ShodanSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("8.8.8.8")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": [{"data": "SSH banner"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.shodan_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.shodan_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.shodan_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("8.8.8.8")
        assert len(leaks) == 1
        assert leaks[0].source_name == "shodan"


# ---------------------------------------------------------------------------
# CensysSource
# ---------------------------------------------------------------------------
class TestCensysSource:
    def _make_source(self):
        from src.modules.sources.censys_source import CensysSource
        return CensysSource(api_key="test_id:test_secret", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.censys_source import CensysSource
        source = CensysSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        hosts_resp = MagicMock()
        hosts_resp.status_code = 200
        hosts_resp.json.return_value = {"result": {"hits": [{"ip": "1.2.3.4"}]}}
        certs_resp = MagicMock()
        certs_resp.status_code = 200
        certs_resp.json.return_value = {"result": {"hits": [{"fingerprint": "abc"}]}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[hosts_resp, certs_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.censys_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.censys_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.censys_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 2


# ---------------------------------------------------------------------------
# ZoomEyeSource
# ---------------------------------------------------------------------------
class TestZoomEyeSource:
    def _make_source(self):
        from src.modules.sources.zoomeye_source import ZoomEyeSource
        return ZoomEyeSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.zoomeye_source import ZoomEyeSource
        source = ZoomEyeSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("8.8.8.8")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"matches": [{"description": "OpenSSH 7.9"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.zoomeye_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.zoomeye_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.zoomeye_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("8.8.8.8")
        assert len(leaks) == 1
        assert leaks[0].source_name == "zoomeye"


# ---------------------------------------------------------------------------
# OTXSource
# ---------------------------------------------------------------------------
class TestOTXSource:
    def _make_source(self):
        from src.modules.sources.otx_source import OTXSource
        return OTXSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.otx_source import OTXSource
        source = OTXSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("example.com")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"domain": "example.com", "alexa": "1000"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.otx_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.otx_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.otx_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "otx"


# ---------------------------------------------------------------------------
# AbuseIPDBSource
# ---------------------------------------------------------------------------
class TestAbuseIPDBSource:
    def _make_source(self):
        from src.modules.sources.abuseipdb_source import AbuseIPDBSource
        return AbuseIPDBSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.abuseipdb_source import AbuseIPDBSource
        source = AbuseIPDBSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("8.8.8.8")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": {"abuseConfidenceScore": 0, "isp": "Google", "countryCode": "US", "totalReports": 0}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.abuseipdb_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.abuseipdb_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.abuseipdb_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("8.8.8.8")
        assert len(leaks) == 1
        assert leaks[0].source_name == "abuseipdb"


# ---------------------------------------------------------------------------
# GreyNoiseSource
# ---------------------------------------------------------------------------
class TestGreyNoiseSource:
    def _make_source(self):
        from src.modules.sources.greynoise_source import GreyNoiseSource
        return GreyNoiseSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.greynoise_source import GreyNoiseSource
        source = GreyNoiseSource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("8.8.8.8")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"classification": "benign", "name": "Google DNS", "seen": True}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.greynoise_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.greynoise_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.greynoise_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("8.8.8.8")
        assert len(leaks) == 1
        assert leaks[0].source_name == "greynoise"


# ---------------------------------------------------------------------------
# IPInfoSource
# ---------------------------------------------------------------------------
class TestIPInfoSource:
    def _make_source(self):
        from src.modules.sources.ipinfo_source import IPInfoSource
        return IPInfoSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"city": "Mountain View", "region": "California", "country": "US", "org": "AS15169 Google LLC"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.ipinfo_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.ipinfo_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.ipinfo_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("8.8.8.8")
        assert len(leaks) == 1
        assert leaks[0].source_name == "ipinfo"


# ---------------------------------------------------------------------------
# WiGLESource
# ---------------------------------------------------------------------------
class TestWiGLESource:
    def _make_source(self):
        from src.modules.sources.wigle_source import WiGLESource
        return WiGLESource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.wigle_source import WiGLESource
        source = WiGLESource(api_key="", request_delay=0.0, timeout=5.0)
        leaks = await source.search_for_address("MyNetwork")
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": [{"ssid": "MyNetwork", "netid": "AA:BB:CC:DD:EE:FF", "encryption": "WPA2"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.wigle_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.wigle_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.wigle_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("MyNetwork")
        assert len(leaks) == 1
        assert leaks[0].source_name == "wigle"


# ---------------------------------------------------------------------------
# PulsediveSource
# ---------------------------------------------------------------------------
class TestPulsediveSource:
    def _make_source(self):
        from src.modules.sources.pulsedive_source import PulsediveSource
        return PulsediveSource(api_key="test_key", request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_key(self):
        from src.modules.sources.pulsedive_source import PulsediveSource
        with patch.dict(os.environ, {"PULSEDIVE_API_KEY": ""}, clear=False):
            source = PulsediveSource(api_key="", request_delay=0.0, timeout=5.0)
            source.api_key = ""
            leaks = await source.search_for_address("evil.com")
            assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"risk": "high", "threats": ["malware"], "attributes": {"type": "domain"}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.pulsedive_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.pulsedive_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.pulsedive_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("evil.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "pulsedive"


# ---------------------------------------------------------------------------
# URLhausSource
# ---------------------------------------------------------------------------
class TestURLhausSource:
    def _make_source(self):
        from src.modules.sources.urlhaus_source import URLhausSource
        return URLhausSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"query_status": "ok", "urls": [{"url": "http://evil.com/malware", "url_status": "online", "threat": "malware_download", "tags": ["elf"]}]}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.urlhaus_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.urlhaus_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.urlhaus_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("evil.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "urlhaus"


# ---------------------------------------------------------------------------
# MaltegoSource
# ---------------------------------------------------------------------------
class TestMaltegoSource:
    def _make_source(self):
        from src.modules.sources.maltego_source import MaltegoSource
        return MaltegoSource(request_delay=0.0, timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_success(self):
        source = self._make_source()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": [{"type": "domain", "value": "example.com"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.sources.maltego_source.httpx.AsyncClient", return_value=mock_client):
            with patch("src.modules.sources.maltego_source.asyncio.sleep", new_callable=AsyncMock):
                with patch("src.modules.sources.maltego_source.time.monotonic", return_value=0.0):
                    leaks = await source.search_for_address("example.com")
        assert len(leaks) == 1
        assert leaks[0].source_name == "maltego"


# ---------------------------------------------------------------------------
# ReconNgSource
# ---------------------------------------------------------------------------
class TestReconNgSource:
    def _make_source(self):
        from src.modules.sources.recon_ng_source import ReconNgSource
        return ReconNgSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.recon_ng_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# SubfinderSource
# ---------------------------------------------------------------------------
class TestSubfinderSource:
    def _make_source(self):
        from src.modules.sources.subfinder_source import SubfinderSource
        return SubfinderSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.subfinder_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# HttpxSource
# ---------------------------------------------------------------------------
class TestHttpxSource:
    def _make_source(self):
        from src.modules.sources.httpx_source import HttpxSource
        return HttpxSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.httpx_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []


# ---------------------------------------------------------------------------
# NmapSource
# ---------------------------------------------------------------------------
class TestNmapSource:
    def _make_source(self):
        from src.modules.sources.nmap_source import NmapSource
        return NmapSource(timeout=5.0)

    @pytest.mark.asyncio
    async def test_fetch_raw_leaks_empty(self):
        source = self._make_source()
        leaks = await source.fetch_raw_leaks()
        assert leaks == []

    @pytest.mark.asyncio
    async def test_search_for_address_no_binary(self):
        source = self._make_source()
        with patch("src.modules.sources.nmap_source.shutil.which", return_value=None):
            leaks = await source.search_for_address("example.com")
        assert leaks == []
