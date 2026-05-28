"""Additional tests for DataLeaksAggregator to boost coverage."""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from src.modules.data_leaks.aggregator import DataLeaksAggregator
from src.models import BreachRecord, ScanResult, Finding, Severity


@pytest.fixture
def aggregator():
    return DataLeaksAggregator(zkit_salt="test-salt")


@pytest.fixture
def aggregator_with_providers():
    return DataLeaksAggregator(zkit_salt="test-salt", providers=["hibp", "leakcheck"])


class TestProviderDiscovery:
    def test_get_providers_no_filter(self, aggregator):
        """All available providers should be returned."""
        providers = aggregator._get_providers()
        # Depends on which vendor modules are installed; at minimum should return dict
        assert isinstance(providers, dict)

    def test_get_providers_with_filter(self, aggregator_with_providers):
        """Only requested providers should be returned."""
        providers = aggregator_with_providers._get_providers()
        assert isinstance(providers, dict)
        for name in providers:
            assert name in ("hibp", "leakcheck")

    def test_get_providers_import_error_handled(self, aggregator):
        """Missing vendor modules should not crash."""
        with patch.dict("sys.modules", {"src.vendor.chiasmodon.hibp": None}):
            providers = aggregator._get_providers()
            assert isinstance(providers, dict)


class TestProviderQuery:
    @pytest.mark.asyncio
    async def test_query_provider_calls_search(self, aggregator):
        mock_provider = MagicMock()
        mock_provider.search.return_value = {"result": []}
        result = await aggregator._query_provider("test", mock_provider, "test@example.com")
        mock_provider.search.assert_called_once_with("test@example.com")
        assert isinstance(result, dict)


class TestParseProviderResults:
    def test_parse_dict_with_result_list(self, aggregator):
        raw = {"status": "ok", "result": [
            {"email": "a@b.com", "source": "TestBreach"},
        ]}
        records = aggregator._parse_provider_results("provider", raw)
        assert len(records) == 1
        assert records[0].email == "a@b.com"
        assert records[0].source == "provider"

    def test_parse_dict_with_results_list(self, aggregator):
        raw = {"results": [{"email": "x@y.com"}]}
        records = aggregator._parse_provider_results("p", raw)
        assert len(records) == 1

    def test_parse_list_input(self, aggregator):
        raw = [{"email": "a@b.com"}, {"email": "c@d.com"}]
        records = aggregator._parse_provider_results("p", raw)
        assert len(records) == 2

    def test_parse_error_status(self, aggregator):
        raw = {"status": "error", "error": "rate limited"}
        records = aggregator._parse_provider_results("p", raw)
        assert len(records) == 0

    def test_parse_non_dict_item_skipped(self, aggregator):
        raw = {"result": ["not a dict", {"email": "a@b.com"}]}
        records = aggregator._parse_provider_results("p", raw)
        assert len(records) == 1

    def test_parse_string_input_returns_empty(self, aggregator):
        records = aggregator._parse_provider_results("p", "invalid")
        assert len(records) == 0

    def test_parse_non_list_result_data(self, aggregator):
        raw = {"result": {"email": "a@b.com"}}
        records = aggregator._parse_provider_results("p", raw)
        assert len(records) == 1

    def test_parse_with_uppercase_fields(self, aggregator):
        raw = [{"Email": "a@b.com", "Username": "user1", "Domain": "example.com", "Description": "test"}]
        records = aggregator._parse_provider_results("p", raw)
        assert records[0].email == "a@b.com"
        assert records[0].username == "user1"
        assert records[0].domain == "example.com"

    def test_parse_with_data_classes(self, aggregator):
        raw = [{"email": "a@b.com", "data_classes": ["password", "email"]}]
        records = aggregator._parse_provider_results("p", raw)
        assert records[0].data_classes == ["password", "email"]


class TestDeduplication:
    def test_deduplicate_same_email_same_source(self, aggregator):
        records = [
            BreachRecord(source="s1", email="a@b.com", description="first"),
            BreachRecord(source="s1", email="a@b.com", description="second"),
        ]
        deduped = aggregator._deduplicate(records)
        assert len(deduped) == 1

    def test_deduplicate_same_email_different_source(self, aggregator):
        records = [
            BreachRecord(source="s1", email="a@b.com"),
            BreachRecord(source="s2", email="a@b.com"),
        ]
        deduped = aggregator._deduplicate(records)
        assert len(deduped) == 2

    def test_deduplicate_uses_username_when_no_email(self, aggregator):
        records = [
            BreachRecord(source="s1", username="user1"),
            BreachRecord(source="s1", username="user1"),
            BreachRecord(source="s1", username="user2"),
        ]
        deduped = aggregator._deduplicate(records)
        assert len(deduped) == 2


class TestFilterFalsePositives:
    def test_filters_by_email(self, aggregator):
        aggregator._false_positives = [{"email": "fp@test.com", "username": None}]
        records = [
            BreachRecord(source="s", email="fp@test.com"),
            BreachRecord(source="s", email="real@test.com"),
        ]
        assert len(aggregator._filter_false_positives(records)) == 1

    def test_filters_by_username(self, aggregator):
        aggregator._false_positives = [{"email": None, "username": "fp_user"}]
        records = [
            BreachRecord(source="s", username="fp_user"),
            BreachRecord(source="s", username="real_user"),
        ]
        assert len(aggregator._filter_false_positives(records)) == 1

    def test_no_false_positives(self, aggregator):
        records = [BreachRecord(source="s", email="a@b.com")]
        assert len(aggregator._filter_false_positives(records)) == 1


class TestSearchIntegration:
    @pytest.mark.asyncio
    async def test_search_with_providers(self, aggregator):
        mock_provider = MagicMock()
        mock_provider.search.return_value = {
            "result": [{"email": "a@b.com", "source": "TestBreach", "description": "test"}]
        }

        with patch.object(aggregator, "_get_providers", return_value={"test": mock_provider}), \
             patch.object(aggregator._checker, "score_severity", return_value=Severity.HIGH):
            result = await aggregator.search("test@example.com")

        assert result.status == "ok"
        assert result.module == "data_leaks"
        assert result.target == "test@example.com"
        assert len(result.breach_records) >= 1

    @pytest.mark.asyncio
    async def test_search_with_provider_exception(self, aggregator):
        mock_provider = MagicMock()
        mock_provider.search.side_effect = RuntimeError("connection failed")

        with patch.object(aggregator, "_get_providers", return_value={"bad": mock_provider}):
            result = await aggregator.search("test@example.com")

        assert result.status == "partial"
        assert "bad" in result.metadata["providers_errored"]

    @pytest.mark.asyncio
    async def test_search_with_error_dict(self, aggregator):
        mock_provider = MagicMock()
        mock_provider.search.return_value = {"status": "error", "error": "rate limited"}

        with patch.object(aggregator, "_get_providers", return_value={"p": mock_provider}):
            result = await aggregator.search("test@example.com")

        assert result.status == "partial"
        assert "p" in result.metadata["providers_errored"]

    @pytest.mark.asyncio
    async def test_search_high_severity_creates_finding(self, aggregator):
        mock_provider = MagicMock()
        mock_provider.search.return_value = {
            "result": [{"email": "a@b.com", "source": "BigBreach", "description": "critical leak"}]
        }

        with patch.object(aggregator, "_get_providers", return_value={"p": mock_provider}), \
             patch.object(aggregator._checker, "score_severity", return_value=Severity.CRITICAL):
            result = await aggregator.search("a@b.com")

        assert result.finding_count >= 1
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_scan_is_alias(self, aggregator):
        with patch.object(aggregator, "search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = ScanResult(
                scan_id="t", module="data_leaks", target="test"
            )
            result = await aggregator.scan("test")
            mock_search.assert_called_once_with("test")


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_scan_result(self, aggregator):
        scan = ScanResult(
            scan_id="t", module="data_leaks", target="test@example.com",
            breach_records=[
                BreachRecord(source="hibp", email="a@b.com", domain="b.com", severity=Severity.HIGH),
                BreachRecord(source="leakcheck", email="a@b.com", severity=Severity.CRITICAL),
            ],
            findings=[],
        )
        result = await aggregator.analyze(scan)
        assert result["total_records"] == 2
        assert result["has_critical"] is True
        assert "hibp" in result["source_breakdown"]

    @pytest.mark.asyncio
    async def test_analyze_unsupported(self, aggregator):
        result = await aggregator.analyze("bad")
        assert "error" in result


class TestLearn:
    @pytest.mark.asyncio
    async def test_learn_false_negatives(self, aggregator):
        await aggregator.learn({"false_negatives": [{"email": "missed@test.com"}]})
        assert len(aggregator._false_positives) == 0

    @pytest.mark.asyncio
    async def test_learn_empty(self, aggregator):
        await aggregator.learn({})
        assert len(aggregator._false_positives) == 0
