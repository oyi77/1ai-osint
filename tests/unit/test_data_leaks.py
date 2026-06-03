"""Tests for data leaks aggregation module."""

import pytest

from src.modules.data_leaks.aggregator import DataLeaksAggregator
from src.modules.data_leaks.breach_checker import BreachChecker
from src.core.models import BreachRecord, Severity


@pytest.fixture
def aggregator():
    return DataLeaksAggregator(zkit_salt="test-salt")


@pytest.fixture
def checker():
    return BreachChecker()


@pytest.fixture
def sample_breach():
    return BreachRecord(
        source="test_source",
        email="test@example.com",
        username="testuser",
        domain="example.com",
        description="Test breach",
        data_classes=["Email addresses", "Passwords"],
        severity=Severity.MEDIUM,
    )


class TestBreachChecker:
    def test_score_critical(self, checker):
        record = BreachRecord(
            source="test",
            email="a@b.com",
            data_classes=["password", "credit card", "email addresses"],
        )
        severity = checker.score_severity(record)
        assert severity in (Severity.CRITICAL, Severity.HIGH)

    def test_score_high(self, checker):
        record = BreachRecord(
            source="test",
            email="a@b.com",
            data_classes=["password", "email"],
        )
        severity = checker.score_severity(record)
        assert severity in (Severity.HIGH, Severity.MEDIUM)

    def test_score_medium(self, checker):
        record = BreachRecord(
            source="test",
            email="a@b.com",
            data_classes=["email addresses", "username"],
        )
        severity = checker.score_severity(record)
        assert severity in (Severity.MEDIUM, Severity.LOW)

    def test_score_low(self, checker):
        record = BreachRecord(
            source="test",
            email="a@b.com",
            data_classes=["gender"],
        )
        severity = checker.score_severity(record)
        assert severity in (Severity.LOW, Severity.INFO)

    def test_score_empty(self, checker):
        record = BreachRecord(source="test", email="a@b.com", data_classes=[])
        severity = checker.score_severity(record)
        assert severity == Severity.INFO

    def test_score_batch(self, checker, sample_breach):
        records = [sample_breach]
        scored = checker.score_batch(records)
        assert len(scored) == 1
        assert scored[0].severity != Severity.MEDIUM  # Should be rescored


class TestDataLeaksAggregator:
    def test_module_name(self, aggregator):
        assert aggregator.name == "data_leaks"

    def test_zkit_hash(self, aggregator):
        h = aggregator.hash_identity("test@example.com")
        assert len(h) == 64

    def test_deduplicate(self, aggregator):
        records = [
            BreachRecord(source="src1", email="a@b.com", description="dup"),
            BreachRecord(source="src1", email="a@b.com", description="dup again"),
            BreachRecord(source="src2", email="a@b.com", description="diff source"),
        ]
        deduped = aggregator._deduplicate(records)
        assert len(deduped) == 2  # same source deduped, different source kept

    def test_filter_false_positives(self, aggregator):
        aggregator._false_positives = [{"email": "fp@example.com", "username": None}]
        records = [
            BreachRecord(source="s", email="fp@example.com"),
            BreachRecord(source="s", email="real@example.com"),
        ]
        filtered = aggregator._filter_false_positives(records)
        assert len(filtered) == 1
        assert filtered[0].email == "real@example.com"

    def test_parse_provider_results(self, aggregator):
        raw = {
            "status": "ok",
            "result": [
                {"email": "a@b.com", "source": "TestBreach", "description": "test"},
                {"email": "c@d.com", "source": "TestBreach2"},
            ],
        }
        records = aggregator._parse_provider_results("test_provider", raw)
        assert len(records) == 2
        assert records[0].source == "test_provider"
        assert records[0].email == "a@b.com"

    @pytest.mark.asyncio
    async def test_analyze(self, aggregator, sample_breach):
        from src.core.models import ScanResult

        scan = ScanResult(
            scan_id="test",
            module="data_leaks",
            target="test@example.com",
            breach_records=[sample_breach],
            findings=[],
        )
        analysis = await aggregator.analyze(scan)
        assert analysis["total_records"] == 1
        assert "source_breakdown" in analysis

    @pytest.mark.asyncio
    async def test_learn_false_positives(self, aggregator):
        await aggregator.learn({"false_positives": [{"email": "fp@test.com"}]})
        assert len(aggregator._false_positives) == 1
