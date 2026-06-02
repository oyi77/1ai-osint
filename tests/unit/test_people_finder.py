"""Tests for people finder search module."""

import pytest
from unittest.mock import patch, MagicMock

from src.modules.people_finder.search import PeopleFinderSearch


@pytest.fixture
def finder():
    return PeopleFinderSearch(zkit_salt="test-salt")


@pytest.fixture
def sherlock_result():
    return {
        "GitHub": {
            "url": "https://github.com/testuser",
            "status": "Claimed",
            "username": "testuser",
        },
        "Twitter": {
            "url": "https://twitter.com/testuser",
            "status": "Claimed",
            "username": "testuser",
        },
    }


@pytest.fixture
def maigret_result():
    return {
        "GitHub": {
            "url": "https://github.com/testuser",
            "status": "Claimed",
            "username": "testuser",
        },
        "Reddit": {
            "url": "https://reddit.com/user/testuser",
            "status": "Claimed",
            "username": "testuser",
        },
    }


@pytest.fixture
def whatsmyname_result():
    return [
        {
            "platform": "Instagram",
            "url": "https://instagram.com/testuser",
            "status": "claimed",
            "username": "testuser",
        },
    ]


class TestE164Validation:
    pass


class TestPeopleFinderSearch:
    def test_module_name(self, finder):
        assert finder.name == "people_finder"

    def test_parse_sherlock_results(self, finder, sherlock_result):
        profiles = finder._parse_provider_results("sherlock", sherlock_result)
        assert len(profiles) == 2
        platforms = {p["platform"] for p in profiles}
        assert "GitHub" in platforms
        assert "Twitter" in platforms
        assert all(p["source_provider"] == "sherlock" for p in profiles)

    def test_parse_maigret_results(self, finder, maigret_result):
        profiles = finder._parse_provider_results("maigret", maigret_result)
        assert len(profiles) == 2
        platforms = {p["platform"] for p in profiles}
        assert "GitHub" in platforms
        assert "Reddit" in platforms

    def test_parse_whatsmyname_results(self, finder, whatsmyname_result):
        profiles = finder._parse_provider_results("whatsmyname", whatsmyname_result)
        assert len(profiles) == 1
        assert profiles[0]["platform"] == "Instagram"

    def test_parse_error_result(self, finder):
        profiles = finder._parse_provider_results("sherlock", {"error": "failed"})
        assert len(profiles) == 0

    def test_parse_empty_result(self, finder):
        profiles = finder._parse_provider_results("sherlock", {})
        assert len(profiles) == 0

    def test_deduplicate_profiles(self, finder):
        raw = [
            {
                "platform": "GitHub",
                "url": "https://github.com/testuser",
                "username": "testuser",
                "status": "found",
                "source_provider": "sherlock",
                "raw_data": {},
            },
            {
                "platform": "GitHub",
                "url": "https://github.com/testuser",
                "username": "testuser",
                "status": "found",
                "source_provider": "maigret",
                "raw_data": {},
            },
            {
                "platform": "Reddit",
                "url": "https://reddit.com/user/testuser",
                "username": "testuser",
                "status": "found",
                "source_provider": "maigret",
                "raw_data": {},
            },
        ]
        profiles = finder._deduplicate_profiles(raw)
        assert len(profiles) == 2
        github = next(p for p in profiles if p.platform == "GitHub")
        assert len(github.source_providers) == 2
        assert "sherlock" in github.source_providers
        assert "maigret" in github.source_providers

    def test_deduplicate_prefers_found_status(self, finder):
        raw = [
            {
                "platform": "Test",
                "url": "https://test.com/user",
                "username": "user",
                "status": "possibly",
                "source_provider": "sherlock",
                "raw_data": {},
            },
            {
                "platform": "Test",
                "url": "https://test.com/user",
                "username": "user",
                "status": "found",
                "source_provider": "maigret",
                "raw_data": {},
            },
        ]
        profiles = finder._deduplicate_profiles(raw)
        assert len(profiles) == 1
        assert profiles[0].status == "found"

    def test_score_confidence_single_provider(self, finder):
        score = PeopleFinderSearch._score_confidence(["sherlock"], 3)
        assert 0.4 <= score <= 0.7

    def test_score_confidence_two_providers(self, finder):
        score = PeopleFinderSearch._score_confidence(["sherlock", "maigret"], 3)
        assert 0.65 <= score <= 0.9

    def test_score_confidence_three_providers(self, finder):
        score = PeopleFinderSearch._score_confidence(
            ["sherlock", "maigret", "whatsmyname"], 3
        )
        assert score >= 0.85

    def test_score_confidence_zero_available(self, finder):
        score = PeopleFinderSearch._score_confidence(["sherlock"], 0)
        assert score == 0.3

    @pytest.mark.asyncio
    async def test_search_integration(
        self, finder, sherlock_result, maigret_result, whatsmyname_result
    ):
        mock_sherlock = MagicMock()
        mock_sherlock.search.return_value = sherlock_result
        mock_maigret = MagicMock()
        mock_maigret.search.return_value = maigret_result
        mock_whatsmyname = MagicMock()
        mock_whatsmyname.search.return_value = whatsmyname_result

        with patch.object(finder, "_get_providers", return_value={
            "sherlock": mock_sherlock,
            "maigret": mock_maigret,
            "whatsmyname": mock_whatsmyname,
        }):
            result = await finder.search("testuser")

        assert result.module == "people_finder"
        assert result.target == "testuser"
        assert result.status == "ok"
        assert result.finding_count > 0
        assert result.metadata["total_profiles"] > 0
        # GitHub should be deduplicated (found by sherlock + maigret)
        github_findings = [
            f for f in result.findings if "GitHub" in f.title
        ]
        assert len(github_findings) == 1
        assert github_findings[0].confidence > 0.5

    @pytest.mark.asyncio
    async def test_search_partial_on_provider_error(self, finder, sherlock_result):
        mock_sherlock = MagicMock()
        mock_sherlock.search.return_value = sherlock_result
        mock_maigret = MagicMock()
        mock_maigret.search.return_value = {"error": "Maigret failed"}

        with patch.object(finder, "_get_providers", return_value={
            "sherlock": mock_sherlock,
            "maigret": mock_maigret,
        }):
            result = await finder.search("testuser")

        assert result.status == "partial"
        assert "maigret" in result.metadata["providers_errored"]

    @pytest.mark.asyncio
    async def test_search_no_providers(self, finder):
        with patch.object(finder, "_get_providers", return_value={}):
            result = await finder.search("testuser")

        assert result.status == "ok"
        assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_analyze(self, finder, sherlock_result):
        with patch.object(finder, "_get_providers", return_value={
            "sherlock": MagicMock(search=MagicMock(return_value=sherlock_result)),
        }):
            scan = await finder.search("testuser")

        analysis = await finder.analyze(scan)
        assert "total_profiles" in analysis
        assert "platform_breakdown" in analysis
        assert "confidence_breakdown" in analysis

    @pytest.mark.asyncio
    async def test_learn(self, finder):
        await finder.learn({"corrections": []})
        # Should not raise; currently a no-op

    @pytest.mark.asyncio
    async def test_scan_is_alias(self, finder, sherlock_result):
        mock_sherlock = MagicMock()
        mock_sherlock.search.return_value = sherlock_result

        with patch.object(finder, "_get_providers", return_value={
            "sherlock": mock_sherlock,
        }):
            result = await finder.scan("testuser")

        assert result.module == "people_finder"
