"""Unit tests for chronological footprint timeline builder."""

from datetime import datetime, timezone

from src.core.models import BreachRecord, Finding
from src.modules.deep_scan.timeline_builder import TimelineBuilder, parse_datetime


def test_parse_datetime():
    # Naive datetime
    dt_naive = datetime(2026, 6, 2, 10, 0, 0)
    parsed = parse_datetime(dt_naive)
    assert parsed.tzinfo == timezone.utc
    assert parsed.hour == 10

    # Aware datetime
    dt_aware = datetime(2026, 6, 2, 10, 0, 0, tzinfo=timezone.utc)
    parsed = parse_datetime(dt_aware)
    assert parsed == dt_aware

    # Timestamp
    ts = 1780000000.0
    parsed = parse_datetime(ts)
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc

    # String format ISO
    parsed = parse_datetime("2026-06-02T10:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026

    # None and invalid cases
    assert parse_datetime(None) is None
    assert parse_datetime("invalid_date_string") is None


def test_timeline_builder_simple():
    findings = [
        Finding(
            id="f1",
            module="test_module",
            title="Account Created",
            description="Created profile on twitter",
            timestamp=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        ),
        Finding(
            id="f2",
            module="crypto_tracer",
            title="Crypto Transaction",
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            raw_data={
                "transactions": [
                    {
                        "timestamp": "2024-05-01T10:00:00Z",
                        "hash": "txhash123",
                        "from_entity": "Mixer",
                        "to_entity": "Target",
                    }
                ]
            },
        ),
    ]

    breaches = [
        BreachRecord(
            source="DeHashed",
            email="test@example.com",
            breach_date=datetime(2022, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
            description="Leaked creds",
        )
    ]

    timeline = TimelineBuilder.build(findings, breaches)

    # Output should be sorted: breach (2022) -> Account Created (2023) -> Transaction (2024-05)
    # The base finding f2 is skipped since it is mapped to transaction details.
    assert len(timeline) == 3
    assert timeline[0].event == "Credential Leak"
    assert timeline[1].event == "Account Created"
    assert timeline[2].event == "Crypto Transaction"
    assert timeline[0].timestamp < timeline[1].timestamp
    assert timeline[1].timestamp < timeline[2].timestamp
