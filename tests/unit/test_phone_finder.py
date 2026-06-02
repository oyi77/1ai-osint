"""Tests for phone finder lookup module."""

import pytest
from unittest.mock import patch, MagicMock

from src.modules.phone_finder.lookup import PhoneFinderLookup


@pytest.fixture
def lookup():
    return PhoneFinderLookup(zkit_salt="test-salt")


@pytest.fixture
def phoneinfoga_result():
    return {
        "carrier": "Vodafone",
        "country_code": "44",
        "country_name": "United Kingdom",
        "line_type": "mobile",
        "location": "London",
    }


@pytest.fixture
def voip_result():
    return {
        "carrier": "Skype",
        "country_code": "1",
        "country_name": "United States",
        "line_type": "voip",
        "location": "Unknown",
    }


class TestE164Validation:
    def test_valid_e164(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("+14155552671")
        assert is_valid is True
        assert e164 == "+14155552671"

    def test_valid_e164_uk(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("+447911123456")
        assert is_valid is True
        assert e164 == "+447911123456"

    def test_strips_formatting(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("+1 (415) 555-2671")
        assert is_valid is True
        assert e164 == "+14155552671"

    def test_double_zero_prefix(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("0014155552671")
        assert is_valid is True
        assert e164 == "+14155552671"

    def test_invalid_short_number(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("123")
        assert is_valid is False
        assert e164 is None

    def test_invalid_no_plus(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("14155552671")
        # 11 digits starting with 1 is valid when prefixed with +
        assert is_valid is True
        assert e164 == "+14155552671"

    def test_invalid_letters(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("not-a-number")
        assert is_valid is False
        assert e164 is None

    def test_empty_string(self, lookup):
        is_valid, e164 = PhoneFinderLookup.validate_e164("")
        assert is_valid is False
        assert e164 is None


class TestPhoneFinderLookup:
    def test_module_name(self, lookup):
        assert lookup.name == "phone_finder"

    def test_parse_carrier_result(self, lookup, phoneinfoga_result):
        info = lookup._parse_result(
            "+447911123456", "+447911123456", True, phoneinfoga_result
        )
        assert info.carrier == "Vodafone"
        assert info.country_code == "44"
        assert info.country_name == "United Kingdom"
        assert info.line_type == "mobile"
        assert info.location == "London"
        assert info.is_voip is False

    def test_parse_voip_result(self, lookup, voip_result):
        info = lookup._parse_result(
            "+14155552671", "+14155552671", True, voip_result
        )
        assert info.carrier == "Skype"
        assert info.is_voip is True

    def test_parse_error_result(self, lookup):
        info = lookup._parse_result(
            "+14155552671", "+14155552671", True, {"error": "failed"}
        )
        assert info.carrier is None
        assert info.is_voip is None

    def test_parse_empty_result(self, lookup):
        info = lookup._parse_result(
            "+14155552671", "+14155552671", True, {}
        )
        assert info.carrier is None

    def test_parse_invalid_number(self, lookup):
        info = lookup._parse_result("bad", None, False, {})
        assert info.is_valid_e164 is False
        assert info.e164_format is None

    @pytest.mark.asyncio
    async def test_search_integration(self, lookup, phoneinfoga_result):
        mock_provider = MagicMock()
        mock_provider.search.return_value = phoneinfoga_result

        with patch.object(lookup, "_get_provider", return_value=mock_provider):
            result = await lookup.search("+447911123456")

        assert result.module == "phone_finder"
        assert result.target == "+447911123456"
        assert result.status == "ok"
        assert result.finding_count > 0
        assert result.metadata["is_valid_e164"] is True
        assert result.metadata["e164_format"] == "+447911123456"

        # Should have carrier and location findings
        titles = [f.title for f in result.findings]
        assert any("Vodafone" in t for t in titles)
        assert any("London" in t for t in titles)

    @pytest.mark.asyncio
    async def test_search_voip_detection(self, lookup, voip_result):
        mock_provider = MagicMock()
        mock_provider.search.return_value = voip_result

        with patch.object(lookup, "_get_provider", return_value=mock_provider):
            result = await lookup.search("+14155552671")

        assert result.status == "ok"
        titles = [f.title for f in result.findings]
        assert any("VoIP" in t for t in titles)

    @pytest.mark.asyncio
    async def test_search_no_provider(self, lookup):
        with patch.object(lookup, "_get_provider", return_value=None):
            result = await lookup.search("+14155552671")

        assert result.status == "error"
        assert "not available" in (result.error or "")

    @pytest.mark.asyncio
    async def test_search_provider_error(self, lookup):
        mock_provider = MagicMock()
        mock_provider.search.return_value = {"error": "PhoneInfoga failed"}

        with patch.object(lookup, "_get_provider", return_value=mock_provider):
            result = await lookup.search("+14155552671")

        assert result.status == "partial"
        assert "phoneinfoga" in result.metadata["providers_errored"]

    @pytest.mark.asyncio
    async def test_analyze(self, lookup, phoneinfoga_result):
        mock_provider = MagicMock()
        mock_provider.search.return_value = phoneinfoga_result

        with patch.object(lookup, "_get_provider", return_value=mock_provider):
            scan = await lookup.search("+447911123456")

        analysis = await lookup.analyze(scan)
        assert "total_findings" in analysis
        assert analysis["is_valid_e164"] is True
        assert analysis["carrier"] == "Vodafone"
        assert analysis["is_voip"] is False

    @pytest.mark.asyncio
    async def test_learn(self, lookup):
        await lookup.learn({"corrections": []})
        # Should not raise; currently a no-op

    @pytest.mark.asyncio
    async def test_scan_is_alias(self, lookup, phoneinfoga_result):
        mock_provider = MagicMock()
        mock_provider.search.return_value = phoneinfoga_result

        with patch.object(lookup, "_get_provider", return_value=mock_provider):
            result = await lookup.scan("+447911123456")

        assert result.module == "phone_finder"
