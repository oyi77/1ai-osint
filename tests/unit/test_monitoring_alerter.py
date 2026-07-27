"""Tests for AlertDispatcher + ConsoleAlerter + FileAlerter
(dedup, dispatch, format)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from src.modules.monitoring.alerter import (
    AlertDispatcher,
    BaseAlerter,
    ConsoleAlerter,
    FileAlerter,
)
from src.modules.monitoring.models import ChangeEvent, ChangeSeverity, ChangeType

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def make_event(
    target: str = "tester",
    change_type: ChangeType = ChangeType.NEW_EMAIL,
    old_value: str | None = None,
    new_value: str | None = "new@x.com",
    severity: ChangeSeverity = ChangeSeverity.MEDIUM,
    description: str = "Email discovered",
) -> ChangeEvent:
    return ChangeEvent(
        event_id=f"ce-test-{id(target)}",
        target=target,
        change_type=change_type,
        old_value=old_value,
        new_value=new_value,
        severity=severity,
        description=description,
        source_module="monitoring",
        timestamp=datetime.now(timezone.utc),
    )


# ------------------------------------------------------------------
# BaseAlerter — deduplication
# ------------------------------------------------------------------


class TestBaseAlerterDedup:
    def test_send_deduplicates_identical_events(self):
        class TestAlerter(BaseAlerter):
            def _deliver(self, event, formatted):
                self.called = True

        alerter = TestAlerter(dedup_window_minutes=60)
        event = make_event()
        assert alerter.send(event) is True  # first time sent
        assert alerter.send(event) is False  # duplicate suppressed

    def test_different_events_not_deduplicated(self):
        alerter = _TestAlerter()
        e1 = make_event(target="alice")
        e2 = make_event(target="bob")
        assert alerter.send(e1) is True
        assert alerter.send(e2) is True

    def test_different_type_not_deduplicated(self):
        alerter = _TestAlerter()
        e1 = make_event(change_type=ChangeType.NEW_EMAIL, new_value="x@y.com")
        e2 = make_event(change_type=ChangeType.NEW_HANDLE, new_value="x@y.com")
        assert alerter.send(e1) is True
        assert alerter.send(e2) is True

    def test_dedup_window_expiry(self):
        """With dedup_window_minutes=0 entries expire immediately after being added."""
        alerter = _TestAlerter(dedup_window_minutes=0)
        event = make_event()
        # First call sends
        assert alerter.send(event) is True
        # With window=0, the entry expires before the second call
        # so the second call also gets sent
        assert alerter.send(event) is True

    def test_stale_entries_are_purged(self):
        """Old entries in the dedup window get cleaned up."""
        alerter = _TestAlerter(dedup_window_minutes=1)
        # Manually insert a stale key
        stale_key = "tester:new_email:new@x.com:"
        alerter._recent_events[stale_key] = datetime.now(timezone.utc) - timedelta(hours=2)
        # New event with same key should be treated as fresh after purge
        event = make_event()
        result = alerter.send(event)
        # Since stale key was purged, it's not a duplicate
        assert result is True

    def test_send_returns_false_on_delivery_failure(self):
        """When _deliver raises an exception, send returns False."""
        alerter = _TestAlerter()
        alerter._deliver = MagicMock(side_effect=RuntimeError("fail"))
        event = make_event()
        assert alerter.send(event) is False

    def test_send_returns_true_on_success(self):
        alerter = _TestAlerter()
        alerter._deliver = MagicMock()
        event = make_event()
        assert alerter.send(event) is True


# ------------------------------------------------------------------
# BaseAlerter — formatting
# ------------------------------------------------------------------


class TestBaseAlerterFormat:
    def test_format_event_basic(self):
        event = make_event()
        text = BaseAlerter.format_event(event)
        assert "## Change Event:" in text
        assert "**Target:** tester" in text
        assert "**Type:** new_email" in text
        assert "**Severity:** medium" in text
        assert "**New value:**" in text
        assert "**Description:** Email discovered" in text

    def test_format_event_with_old_value(self):
        event = make_event(old_value="old@x.com", new_value="new@x.com")
        text = BaseAlerter.format_event(event)
        assert "**Old value:**" in text
        assert "**New value:**" in text

    def test_format_event_without_optional_fields(self):
        event = make_event(old_value=None, new_value=None)
        text = BaseAlerter.format_event(event)
        assert "**Old value:**" not in text
        assert "**New value:**" not in text

    def test_format_event_json(self):
        event = make_event()
        raw = BaseAlerter.format_event_json(event)
        data = json.loads(raw)
        assert data["event_id"] == event.event_id
        assert data["target"] == "tester"
        assert data["change_type"] == "new_email"


# ------------------------------------------------------------------
# ConsoleAlerter
# ------------------------------------------------------------------


class TestConsoleAlerter:
    def test_deliver_prints(self, capsys):
        alerter = ConsoleAlerter()
        event = make_event()
        alerter.send(event)
        captured = capsys.readouterr()
        assert "[ALERT MEDIUM] tester: Email discovered" in captured.out

    def test_deliver_high_severity(self, capsys):
        alerter = ConsoleAlerter()
        event = make_event(severity=ChangeSeverity.HIGH)
        alerter.send(event)
        captured = capsys.readouterr()
        assert "[ALERT HIGH]" in captured.out


# ------------------------------------------------------------------
# FileAlerter
# ------------------------------------------------------------------


class TestFileAlerter:
    def test_deliver_writes_jsonl(self, tmp_path: Path):
        log_dir = tmp_path / "alerts"
        alerter = FileAlerter(log_dir=log_dir)
        event = make_event()
        alerter.send(event)

        # Find the log file
        log_files = list(log_dir.glob("*.jsonl"))
        assert len(log_files) == 1
        content = log_files[0].read_text(encoding="utf-8")
        assert event.event_id in content
        assert "new_email" in content

    def test_log_dir_created(self, tmp_path: Path):
        log_dir = tmp_path / "nonexistent" / "deep"
        assert not log_dir.exists()
        FileAlerter(log_dir=log_dir)
        assert log_dir.exists()

    def test_current_log_uses_today_date(self, tmp_path: Path):
        alerter = FileAlerter(log_dir=tmp_path)
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        log_path = alerter._current_log()
        assert today in log_path.name

    def test_deliver_appends_multiple_events(self, tmp_path: Path):
        log_dir = tmp_path / "alerts"
        alerter = FileAlerter(log_dir=log_dir)
        alerter.send(make_event(target="a"))
        alerter.send(make_event(target="b"))

        log_files = list(log_dir.glob("*.jsonl"))
        assert len(log_files) == 1
        lines = log_files[0].read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2


# ------------------------------------------------------------------
# AlertDispatcher
# ------------------------------------------------------------------


class TestAlertDispatcher:
    def test_dispatch_fires_console(self, capsys):
        dispatcher = AlertDispatcher()
        event = make_event()
        count = dispatcher.dispatch([event])
        assert count == 1
        captured = capsys.readouterr()
        assert "[ALERT" in captured.out

    def test_dispatch_dedup_counts_correctly(self, capsys):
        """Duplicate event through console counts as 0 sent."""
        dispatcher = AlertDispatcher()
        event = make_event()
        dispatcher.dispatch([event])  # first
        capsys.readouterr()  # flush
        count = dispatcher.dispatch([event])  # duplicate
        assert count == 0  # deduplicated

    def test_dispatch_multiple_events(self, capsys):
        dispatcher = AlertDispatcher()
        events = [
            make_event(target="a", new_value="a@x.com"),
            make_event(target="b", new_value="b@x.com"),
            make_event(target="c", new_value="c@x.com"),
        ]
        count = dispatcher.dispatch(events)
        assert count == 3

    def test_dispatch_empty_list(self):
        dispatcher = AlertDispatcher()
        assert dispatcher.dispatch([]) == 0

    def test_dispatch_unknown_channel_warning(self, caplog):
        dispatcher = AlertDispatcher()
        event = make_event()
        import logging

        caplog.set_level(logging.WARNING)
        dispatcher.dispatch([event], channels=["nonexistent"])
        assert "Unknown alert channel" in caplog.text

    def test_dispatch_specific_channels(self, capsys):
        dispatcher = AlertDispatcher()
        event = make_event()
        count = dispatcher.dispatch([event], channels=["console"])
        assert count == 1
        captured = capsys.readouterr()
        assert "[ALERT" in captured.out

    def test_dispatch_custom_channel_only(self):
        dispatcher = AlertDispatcher()
        mock_alerter = _TestAlerter()
        mock_alerter._deliver = MagicMock()

        dispatcher.register_channel("custom", mock_alerter)
        event = make_event()
        count = dispatcher.dispatch([event], channels=["custom"])
        assert count == 1
        mock_alerter._deliver.assert_called_once()

    def test_register_channel_replace(self):
        dispatcher = AlertDispatcher()
        a1 = _TestAlerter()
        a2 = _TestAlerter()
        dispatcher.register_channel("console", a1)
        dispatcher.register_channel("console", a2)  # replace
        assert dispatcher._channels["console"] is a2

    def test_dispatch_events_markdown(self):
        dispatcher = AlertDispatcher()
        events = [
            make_event(target="alice", new_value="alice@x.com"),
            make_event(target="bob", new_value="bob@x.com"),
        ]
        md = dispatcher.dispatch_events_markdown(events)
        assert "# Change Detection Report" in md
        assert "alice" in md
        assert "bob" in md
        assert "2" in md

    def test_dispatch_events_markdown_empty(self):
        dispatcher = AlertDispatcher()
        md = dispatcher.dispatch_events_markdown([])
        assert "No changes detected." in md


# ------------------------------------------------------------------
# Internal helper
# ------------------------------------------------------------------


class _TestAlerter(BaseAlerter):
    """Minimal alerter for testing base class behaviour."""

    def _deliver(self, event: ChangeEvent, formatted: str) -> None:
        pass
