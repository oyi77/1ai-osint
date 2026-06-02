"""Tests for chiasmodon stub implementations (dehashed, pastebin, reddit, aggregator)."""

from unittest.mock import MagicMock, patch


class TestDeHashedTool:
    def test_search_missing_key(self):
        with patch.dict("os.environ", {}, clear=True):
            from src.vendor.chiasmodon.leak_dehashed import DeHashedTool
            tool = DeHashedTool()
            result = tool.search("test@example.com")
            assert result["status"] == "error"
            assert "DEHASHED_API_KEY" in result["error"]

    def test_search_success(self):
        with patch.dict("os.environ", {"DEHASHED_API_KEY": "user:pass"}):
            from src.vendor.chiasmodon.leak_dehashed import DeHashedTool
            tool = DeHashedTool()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"entries": [{"email": "test@example.com"}], "balance": 1}
            with patch("requests.get", return_value=mock_resp):
                result = tool.search("test@example.com")
            assert result["status"] == "ok"
            assert len(result["result"]) == 1

    def test_search_http_error(self):
        with patch.dict("os.environ", {"DEHASHED_API_KEY": "user:pass"}):
            from src.vendor.chiasmodon.leak_dehashed import DeHashedTool
            tool = DeHashedTool()
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            with patch("requests.get", return_value=mock_resp):
                result = tool.search("test")
            assert result["status"] == "error"
            assert "429" in result["error"]

    def test_scan_not_supported(self):
        from src.vendor.chiasmodon.leak_dehashed import DeHashedTool
        result = DeHashedTool().scan("test")
        assert result["status"] == "error"


class TestPastebinTool:
    def test_search_success(self):
        from src.vendor.chiasmodon.leak_pastebin import PastebinTool
        tool = PastebinTool()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><a href="/abc123">Paste Title</a></body></html>'
        with patch("requests.get", return_value=mock_resp):
            result = tool.search("mnemonic")
        assert result["status"] == "ok"
        assert len(result["result"]) >= 1
        assert "pastebin.com" in result["result"][0]["url"]

    def test_search_http_error(self):
        from src.vendor.chiasmodon.leak_pastebin import PastebinTool
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        with patch("requests.get", return_value=mock_resp):
            result = PastebinTool().search("test")
        assert result["status"] == "error"

    def test_scan_not_supported(self):
        from src.vendor.chiasmodon.leak_pastebin import PastebinTool
        result = PastebinTool().scan("test")
        assert result["status"] == "error"


class TestRedditLeakTool:
    def test_search_success(self):
        from src.vendor.chiasmodon.leak_reddit import RedditLeakTool
        tool = RedditLeakTool()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "children": [
                    {"data": {
                        "title": "Found seed phrase",
                        "permalink": "/r/crypto/comments/abc/found_seed",
                        "subreddit": "crypto",
                        "author": "user1",
                        "created_utc": 1234567890,
                        "selftext": "abandon abandon...",
                    }}
                ]
            }
        }
        with patch("requests.get", return_value=mock_resp):
            result = tool.search("seed phrase")
        assert result["status"] == "ok"
        assert len(result["result"]) == 1
        assert result["result"][0]["subreddit"] == "crypto"

    def test_search_http_error(self):
        from src.vendor.chiasmodon.leak_reddit import RedditLeakTool
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        with patch("requests.get", return_value=mock_resp):
            result = RedditLeakTool().search("test")
        assert result["status"] == "error"

    def test_scan_not_supported(self):
        from src.vendor.chiasmodon.leak_reddit import RedditLeakTool
        result = RedditLeakTool().scan("test")
        assert result["status"] == "error"


class TestLeakAggregatorTool:
    def test_search_with_no_sources(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool
        tool = LeakAggregatorTool()
        tool._sources = []
        result = tool.search("test")
        assert result["status"] == "ok"
        assert result["result"] == []

    def test_search_with_mock_sources(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool
        tool = LeakAggregatorTool()
        mock_source = MagicMock()
        mock_source.name = "mock_source"
        mock_source.search.return_value = {"status": "ok", "result": [{"email": "a@b.com"}]}
        tool._sources = [mock_source]
        result = tool.search("test")
        assert result["status"] == "ok"
        assert len(result["result"]) == 1
        assert result["result"][0]["_source"] == "mock_source"

    def test_search_with_failing_source(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool
        tool = LeakAggregatorTool()
        mock_source = MagicMock()
        mock_source.name = "failing"
        mock_source.search.side_effect = Exception("API down")
        tool._sources = [mock_source]
        result = tool.search("test")
        assert result["status"] == "ok"
        assert len(result["errors"]) == 1

    def test_analyze_empty(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool
        result = LeakAggregatorTool().analyze([])
        assert "No data" in result["note"]

    def test_analyze_with_data(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool
        data = [{"_source": "hibp"}, {"_source": "hibp"}, {"_source": "scylla"}]
        result = LeakAggregatorTool().analyze(data)
        assert result["total_results"] == 3
        assert result["by_source"]["hibp"] == 2

    def test_learn(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool
        tool = LeakAggregatorTool()
        tool.learn({"false_positive": "test@example.com"})
        assert "test@example.com" in tool.feedback["false_positives"]
