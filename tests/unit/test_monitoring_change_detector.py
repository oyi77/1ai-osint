"""Tests for ChangeDetector — set diffs, breach changes, risk changes,
first-scan events."""

from __future__ import annotations

from unittest.mock import ANY, patch

import pytest

from src.modules.monitoring.change_detector import ChangeDetector
from src.modules.monitoring.models import (
    ChangeEvent,
    ChangeSeverity,
    ChangeType,
    WatchlistTarget,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def detector() -> ChangeDetector:
    return ChangeDetector()


@pytest.fixture
def snapshot_no_data() -> dict:
    return {
        "briefing": {
            "subject": {},
            "breach_records": [],
            "risk": {},
        },
    }


@pytest.fixture
def snapshot_with_data() -> dict:
    return {
        "briefing": {
            "subject": {
                "primary_name": "Test User",
                "emails": ["a@x.com", "b@x.com"],
                "known_handles": ["user1", "user2"],
                "domains": ["example.com"],
                "phones": ["+1-555-0100"],
                "crypto_addresses": ["0xabc123def456"],
                "confidence_score": 0.8,
                "city": "New York",
            },
            "breach_records": [
                {"breach_name": "breach1", "date": "2024-01-01"},
                {"breach_name": "breach2", "date": "2024-06-01"},
            ],
            "risk": {
                "risk_score": 45,
                "risk_level": "medium",
                "criticality": "low",
            },
        },
    }


# ------------------------------------------------------------------
# First scan (previous is None)
# ------------------------------------------------------------------

def test_first_scan_no_data(detector: ChangeDetector, snapshot_no_data: dict):
    events = detector.detect_changes(None, snapshot_no_data, target="tester")
    assert events == []


def test_first_scan_all_entity_types(detector: ChangeDetector, snapshot_with_data: dict):
    events = detector.detect_changes(None, snapshot_with_data, target="Test User")
    # 2 emails + 2 handles + 1 domain + 1 phone + 1 crypto = 7
    assert len(events) == 7

    types = {e.change_type for e in events}
    assert ChangeType.NEW_EMAIL in types
    assert ChangeType.NEW_HANDLE in types
    assert ChangeType.NEW_DOMAIN in types
    assert ChangeType.NEW_PHONE in types
    assert ChangeType.NEW_CRYPTO_ADDRESS in types

    # Verify severities
    for e in events:
        if e.change_type == ChangeType.NEW_EMAIL:
            assert e.severity == ChangeSeverity.MEDIUM
        elif e.change_type == ChangeType.NEW_HANDLE:
            assert e.severity == ChangeSeverity.LOW


def test_first_scan_target_default(detector: ChangeDetector, snapshot_with_data: dict):
    """When no target provided, uses primary_name from subject."""
    events = detector.detect_changes(None, snapshot_with_data)
    assert len(events) == 7
    for e in events:
        assert e.target == "Test User"


def test_first_scan_target_fallback(detector: ChangeDetector, snapshot_no_data: dict):
    """When no target and no subject name, falls back to 'unknown'."""
    events = detector.detect_changes(None, snapshot_no_data)
    # With no data, there are no events, so we never exercise the fallback
    # Add a minimal current with subject no name
    current = {"briefing": {"subject": {"emails": ["x@y.com"]}}}
    events = detector.detect_changes(None, current)
    assert len(events) == 1
    assert events[0].target == "unknown"


# ------------------------------------------------------------------
# No changes
# ------------------------------------------------------------------

def test_no_changes(detector: ChangeDetector, snapshot_with_data: dict):
    events = detector.detect_changes(snapshot_with_data, snapshot_with_data, target="tester")
    assert events == []


# ------------------------------------------------------------------
# Set changes — additions
# ------------------------------------------------------------------

def test_new_emails(detector: ChangeDetector):
    prev = {"briefing": {"subject": {"emails": ["a@x.com"]}}}
    curr = {"briefing": {"subject": {"emails": ["a@x.com", "b@x.com", "c@x.com"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    added = [e for e in events if e.change_type == ChangeType.NEW_EMAIL]
    assert len(added) == 2
    added_vals = sorted(e.new_value for e in added)
    assert added_vals == ["b@x.com", "c@x.com"]


def test_new_handles(detector: ChangeDetector):
    prev = {"briefing": {"subject": {"known_handles": ["h1"]}}}
    curr = {"briefing": {"subject": {"known_handles": ["h1", "h2", "h3"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    added = [e for e in events if e.change_type == ChangeType.NEW_HANDLE]
    assert len(added) == 2


def test_new_domain(detector: ChangeDetector):
    prev = {"briefing": {"subject": {}}}
    curr = {"briefing": {"subject": {"domains": ["evil.com"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    assert len(events) == 1
    assert events[0].change_type == ChangeType.NEW_DOMAIN
    assert events[0].new_value == "evil.com"


def test_new_phone(detector: ChangeDetector):
    prev = {"briefing": {"subject": {}}}
    curr = {"briefing": {"subject": {"phones": ["+1-555-0199"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    assert len(events) == 1
    assert events[0].change_type == ChangeType.NEW_PHONE
    assert events[0].severity == ChangeSeverity.MEDIUM


def test_new_crypto_address(detector: ChangeDetector):
    prev = {"briefing": {"subject": {}}}
    curr = {"briefing": {"subject": {"crypto_addresses": ["0xdeadbeef1234567890abcdef"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    assert len(events) == 1
    assert events[0].change_type == ChangeType.NEW_CRYPTO_ADDRESS
    # Set comparison does NOT truncate (only _first_scan_events truncates)
    assert "0xdeadbeef" in events[0].description


# ------------------------------------------------------------------
# Set changes — removals
# ------------------------------------------------------------------

def test_removed_entities(detector: ChangeDetector):
    prev = {"briefing": {"subject": {"emails": ["stay@x.com", "gone@x.com"], "known_handles": ["old_h"]}}}
    curr = {"briefing": {"subject": {"emails": ["stay@x.com"], "known_handles": []}}}
    events = detector.detect_changes(prev, curr, target="tester")
    removals = [e for e in events if e.change_type == ChangeType.SOURCE_DISAPPEARED]
    assert len(removals) == 2
    removed_vals = sorted(e.old_value for e in removals)
    assert removed_vals == ["gone@x.com", "old_h"]


# ------------------------------------------------------------------
# Breach changes
# ------------------------------------------------------------------

def test_new_breach(detector: ChangeDetector):
    prev = {"briefing": {"breach_records": [{"breach_name": "b1"}]}}
    curr = {"briefing": {"breach_records": [{"breach_name": "b1"}, {"breach_name": "b2"}]}}
    events = detector.detect_changes(prev, curr, target="tester")
    new_breaches = [e for e in events if e.change_type == ChangeType.NEW_BREACH]
    assert len(new_breaches) == 1
    assert new_breaches[0].new_value == "b2"
    assert new_breaches[0].severity == ChangeSeverity.HIGH


def test_breach_count_delta(detector: ChangeDetector):
    prev = {"briefing": {"breach_records": [{"breach_name": "b1"}]}}
    curr = {"briefing": {"breach_records": [{"breach_name": "b1"}, {"breach_name": "b2"}, {"breach_name": "b3"}]}}
    events = detector.detect_changes(prev, curr, target="tester")
    count_events = [e for e in events if e.change_type == ChangeType.FIELD_CHANGE]
    assert len(count_events) == 1
    assert "1 → 3" in count_events[0].description


def test_breach_count_large_delta(detector: ChangeDetector):
    """Delta > 2 raises severity to MEDIUM."""
    prev = {"briefing": {"breach_records": []}}
    curr = {"briefing": {"breach_records": [{"breach_name": f"b{i}"} for i in range(5)]}}
    events = detector.detect_changes(prev, curr, target="tester")
    count_events = [e for e in events if e.change_type == ChangeType.FIELD_CHANGE]
    assert len(count_events) == 1
    assert count_events[0].severity == ChangeSeverity.MEDIUM


def test_breach_count_small_delta(detector: ChangeDetector):
    """Delta <= 2 stays LOW."""
    prev = {"briefing": {"breach_records": [{"breach_name": "b1"}]}}
    curr = {"briefing": {"breach_records": [{"breach_name": "b1"}, {"breach_name": "b2"}]}}
    events = detector.detect_changes(prev, curr, target="tester")
    count_events = [e for e in events if e.change_type == ChangeType.FIELD_CHANGE]
    assert len(count_events) == 1
    assert count_events[0].severity == ChangeSeverity.LOW


# ------------------------------------------------------------------
# Risk changes
# ------------------------------------------------------------------

def test_risk_score_change(detector: ChangeDetector):
    prev = {"briefing": {"risk": {"risk_score": 30}}}
    curr = {"briefing": {"risk": {"risk_score": 75}}}
    events = detector.detect_changes(prev, curr, target="tester")
    risk_events = [e for e in events if e.change_type == ChangeType.RISK_SCORE_CHANGE]
    assert len(risk_events) == 1
    assert risk_events[0].old_value == "30"
    assert risk_events[0].new_value == "75"
    assert risk_events[0].severity == ChangeSeverity.HIGH


def test_risk_level_change(detector: ChangeDetector):
    prev = {"briefing": {"risk": {"risk_level": "low"}}}
    curr = {"briefing": {"risk": {"risk_level": "critical"}}}
    events = detector.detect_changes(prev, curr, target="tester")
    risk_events = [e for e in events if e.change_type == ChangeType.RISK_SCORE_CHANGE]
    assert len(risk_events) == 1


def test_risk_multiple_fields_change(detector: ChangeDetector):
    prev = {"briefing": {"risk": {"risk_score": 10, "risk_level": "low", "criticality": "none"}}}
    curr = {"briefing": {"risk": {"risk_score": 80, "risk_level": "high", "criticality": "medium"}}}
    events = detector.detect_changes(prev, curr, target="tester")
    risk_events = [e for e in events if e.change_type == ChangeType.RISK_SCORE_CHANGE]
    assert len(risk_events) == 3


def test_risk_no_change(detector: ChangeDetector):
    prev = {"briefing": {"risk": {"risk_score": 50}}}
    curr = {"briefing": {"risk": {"risk_score": 50}}}
    events = detector.detect_changes(prev, curr, target="tester")
    risk_events = [e for e in events if e.change_type == ChangeType.RISK_SCORE_CHANGE]
    assert len(risk_events) == 0


def test_risk_missing_from_both(detector: ChangeDetector):
    prev = {"briefing": {}}
    curr = {"briefing": {}}
    events = detector.detect_changes(prev, curr, target="tester")
    risk_events = [e for e in events if e.change_type == ChangeType.RISK_SCORE_CHANGE]
    assert len(risk_events) == 0


# ------------------------------------------------------------------
# Attribute changes
# ------------------------------------------------------------------

def test_attribute_change(detector: ChangeDetector):
    prev = {"briefing": {"subject": {"primary_name": "Old Name", "city": "Paris"}}}
    curr = {"briefing": {"subject": {"primary_name": "New Name", "city": "London"}}}
    events = detector.detect_changes(prev, curr, target="tester")
    attr_events = [e for e in events if e.change_type == ChangeType.ATTRIBUTE_CHANGE]
    assert len(attr_events) == 2


def test_attribute_change_only_when_new_value_not_none(detector: ChangeDetector):
    """Attribute change only fires when new_value is not None."""
    prev = {"briefing": {"subject": {"city": "Paris"}}}
    curr = {"briefing": {"subject": {"city": None}}}
    events = detector.detect_changes(prev, curr, target="tester")
    attr_events = [e for e in events if e.change_type == ChangeType.ATTRIBUTE_CHANGE]
    assert len(attr_events) == 0


# ------------------------------------------------------------------
# watchlist_target parameter
# ------------------------------------------------------------------

def test_watchlist_target_passed_but_not_used_yet(detector: ChangeDetector):
    """The watchlist_target parameter is accepted but not yet used in logic."""
    prev = {"briefing": {"subject": {"emails": ["old@x.com"]}}}
    curr = {"briefing": {"subject": {"emails": ["old@x.com", "new@x.com"]}}}
    wt = WatchlistTarget(target="tester", target_type="email")
    events = detector.detect_changes(prev, curr, target="tester", watchlist_target=wt)
    assert len(events) == 1
    assert events[0].change_type == ChangeType.NEW_EMAIL


# ------------------------------------------------------------------
# Event identity
# ------------------------------------------------------------------

def test_event_ids_are_unique(detector: ChangeDetector):
    prev = {"briefing": {"subject": {"emails": []}}}
    curr = {"briefing": {"subject": {"emails": ["a@x.com", "b@x.com", "c@x.com"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    ids = [e.event_id for e in events]
    assert len(set(ids)) == len(ids)


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------

def test_empty_briefing(detector: ChangeDetector):
    prev = {}
    curr = {}
    events = detector.detect_changes(prev, curr, target="tester")
    assert events == []


def test_missing_fields_in_prev(detector: ChangeDetector):
    prev = {"briefing": {}}
    curr = {"briefing": {"subject": {"emails": ["a@x.com"]}}}
    events = detector.detect_changes(prev, curr, target="tester")
    assert len(events) == 1
    assert events[0].change_type == ChangeType.NEW_EMAIL


def test_breach_records_empty_prev_non_empty_curr(detector: ChangeDetector):
    prev = {"briefing": {"breach_records": []}}
    curr = {"briefing": {"breach_records": [{"breach_name": "b1"}, {"breach_name": "b2"}]}}
    events = detector.detect_changes(prev, curr, target="tester")
    new_breaches = [e for e in events if e.change_type == ChangeType.NEW_BREACH]
    assert len(new_breaches) == 2
