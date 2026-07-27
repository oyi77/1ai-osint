"""Tests for leak_finder coordinator data and constants."""

from datetime import datetime, timezone

from src.modules.crypto.leak_finder.coordinator import (
    _SOURCE_MAP,
    ALL_SOURCES,
    LeakFinderResult,
)


class TestLeakFinderResult:
    def test_defaults(self):
        r = LeakFinderResult()
        assert r.raw_leaks_fetched == 0
        assert r.keys_extracted == 0
        assert r.keys_deduplicated == 0
        assert r.addresses_checked == 0
        assert r.funded_wallets == 0
        assert r.sweep_results == []
        assert r.errors == []
        assert r.completed_at is None

    def test_elapsed_seconds_no_completion(self):
        r = LeakFinderResult()
        assert r.elapsed_seconds == 0.0

    def test_elapsed_seconds_with_completion(self):
        started = datetime(2026, 1, 1, tzinfo=timezone.utc)
        completed = datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
        r = LeakFinderResult(started_at=started, completed_at=completed)
        assert r.elapsed_seconds == 5.0

    def test_custom_values(self):
        r = LeakFinderResult(
            raw_leaks_fetched=10,
            keys_extracted=5,
            keys_deduplicated=3,
            addresses_checked=2,
            funded_wallets=1,
            errors=["test error"],
        )
        assert r.raw_leaks_fetched == 10
        assert r.keys_extracted == 5
        assert r.keys_deduplicated == 3
        assert r.funded_wallets == 1
        assert len(r.errors) == 1


class TestSourceMap:
    def test_all_sources_in_source_map(self):
        for source in ALL_SOURCES:
            assert source in _SOURCE_MAP

    def test_source_map_has_expected_sources(self):
        assert "github" in _SOURCE_MAP
        assert "paste" in _SOURCE_MAP
        assert "telegram" in _SOURCE_MAP
        assert "tgstat" in _SOURCE_MAP

    def test_source_map_classes(self):
        from src.modules.crypto.leak_finder.sources.github_source import GitHubLeakSource
        from src.modules.crypto.leak_finder.sources.paste_source import PasteSource

        assert _SOURCE_MAP["github"] is GitHubLeakSource
        assert _SOURCE_MAP["paste"] is PasteSource

    def test_invalid_source_not_in_map(self):
        assert "invalid" not in _SOURCE_MAP
        assert "nonexistent" not in ALL_SOURCES


class TestCoordinatorInit:
    def test_init_defaults(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator

        coord = LeakFinderCoordinator()
        assert coord._source_names == list(ALL_SOURCES)
        assert coord._github_token == ""

    def test_init_with_sources(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator

        coord = LeakFinderCoordinator(sources=["github", "paste"])
        assert coord._source_names == ["github", "paste"]

    def test_init_with_github_token(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator

        coord = LeakFinderCoordinator(github_token="ghp_test123")
        assert coord._github_token == "ghp_test123"

    def test_init_with_custom_concurrency(self):
        from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator

        coord = LeakFinderCoordinator(api_concurrency=10)
        assert coord._api_concurrency == 10
