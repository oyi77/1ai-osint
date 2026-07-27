"""Tests for WatchlistManager — CRUD, persistence, due-targets."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from src.modules.monitoring.models import WatchlistTarget
from src.modules.monitoring.watchlist import WatchlistManager

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def tmp_storage(tmp_path: Path) -> Path:
    """Provide a temporary storage dir that can be reused across tests."""
    return tmp_path / "watchlist_test"


@pytest.fixture
def manager(tmp_storage: Path) -> WatchlistManager:
    """WatchlistManager backed by a temporary dir (avoids real Settings)."""
    return WatchlistManager(storage_dir=tmp_storage)


@pytest.fixture
def populated_manager(manager: WatchlistManager) -> WatchlistManager:
    """Manager pre-populated with a few targets."""
    manager.add_target("alice@example.com", "email", tags=["dev"], interval_hours=2)
    manager.add_target("bob@example.com", "email", tags=["ops"], interval_hours=48)
    manager.add_target("malicious.io", "domain", tags=["dev", "malicious"], interval_hours=6)
    return manager


# ------------------------------------------------------------------
# Initialisation
# ------------------------------------------------------------------


def test_init_creates_storage_dir(tmp_storage: Path):
    assert not tmp_storage.exists()
    WatchlistManager(storage_dir=tmp_storage)
    assert tmp_storage.exists()


def test_init_default_storage_dir():
    """Using default storage_dir should resolve via Settings."""
    with patch("src.modules.monitoring.watchlist.Settings") as mock_settings:
        mock_settings.return_value.project_root = Path("/tmp/fake_root")
        mgr = WatchlistManager()
        expected = Path("/tmp/fake_root") / "investigations" / "watchlist"
        assert mgr._storage_dir == expected


# ------------------------------------------------------------------
# CRUD — add
# ------------------------------------------------------------------


def test_add_target(manager: WatchlistManager):
    obj = manager.add_target("test@example.com", "email", tags=["a", "b"])
    assert isinstance(obj, WatchlistTarget)
    assert obj.target == "test@example.com"
    assert obj.target_type == "email"
    assert obj.tags == ["a", "b"]
    assert obj.interval_hours == 24
    assert obj.alert_channels == ["console"]
    assert obj.last_scan is None
    assert manager.count() == 1


def test_add_target_normalises_key(manager: WatchlistManager):
    manager.add_target("  Alice@Example.COM  ", "email")
    obj = manager.get_target("alice@example.com")
    assert obj is not None
    assert obj.target == "  Alice@Example.COM  "  # original preserved


def test_add_target_min_interval(manager: WatchlistManager):
    """interval_hours is clamped to minimum 1."""
    obj = manager.add_target("x@y.com", "email", interval_hours=0)
    assert obj.interval_hours == 1


def test_add_target_defaults(manager: WatchlistManager):
    obj = manager.add_target("x@y.com", "email")
    assert obj.tags == []
    assert obj.alert_channels == ["console"]
    assert obj.severity_threshold == "medium"
    assert obj.context == {}


def test_add_target_update_preserves_last_scan(manager: WatchlistManager):
    """Re-adding the same target preserves created_at and last_scan."""
    obj1 = manager.add_target("x@y.com", "email")
    assert obj1.created_at is not None
    past = datetime.now(timezone.utc) - timedelta(hours=5)
    manager.mark_scanned("x@y.com", at=past)

    obj2 = manager.add_target("x@y.com", "email", tags=["updated"])
    assert obj2.created_at == obj1.created_at
    assert obj2.last_scan == past
    assert obj2.tags == ["updated"]
    assert obj2.updated_at > obj1.updated_at


# ------------------------------------------------------------------
# CRUD — remove
# ------------------------------------------------------------------


def test_remove_target_exists(manager: WatchlistManager):
    manager.add_target("x@y.com", "email")
    assert manager.remove_target("x@y.com") is True
    assert manager.count() == 0


def test_remove_target_not_exists(manager: WatchlistManager):
    assert manager.remove_target("nobody@example.com") is False


def test_remove_target_normalised(manager: WatchlistManager):
    manager.add_target("X@Y.COM", "email")
    assert manager.remove_target("x@y.com") is True


# ------------------------------------------------------------------
# CRUD — list / get
# ------------------------------------------------------------------


def test_list_targets_all(populated_manager: WatchlistManager):
    targets = populated_manager.list_targets()
    assert len(targets) == 3


def test_list_targets_by_type(populated_manager: WatchlistManager):
    emails = populated_manager.list_targets(target_type="email")
    assert len(emails) == 2
    domains = populated_manager.list_targets(target_type="domain")
    assert len(domains) == 1


def test_list_targets_by_tag(populated_manager: WatchlistManager):
    devs = populated_manager.list_targets(tag="dev")
    assert len(devs) == 2
    ops = populated_manager.list_targets(tag="ops")
    assert len(ops) == 1


def test_list_targets_sorted(populated_manager: WatchlistManager):
    targets = populated_manager.list_targets()
    assert targets[0].target.startswith("alice")
    assert targets[1].target.startswith("bob")
    assert targets[2].target.startswith("malicious")


def test_get_target_exists(populated_manager: WatchlistManager):
    obj = populated_manager.get_target("alice@example.com")
    assert obj is not None
    assert obj.target_type == "email"


def test_get_target_not_exists(populated_manager: WatchlistManager):
    assert populated_manager.get_target("ghost@example.com") is None


def test_get_target_normalised(populated_manager: WatchlistManager):
    assert populated_manager.get_target("ALICE@EXAMPLE.COM") is not None


# ------------------------------------------------------------------
# Due targets
# ------------------------------------------------------------------


def test_get_due_targets_all_new(manager: WatchlistManager):
    """All targets with no last_scan are due."""
    manager.add_target("a@x.com", "email")
    manager.add_target("b@x.com", "email")
    due = manager.get_due_targets()
    assert len(due) == 2


def test_get_due_targets_some_due(manager: WatchlistManager):
    manager.add_target("frequent@x.com", "email", interval_hours=1)
    manager.add_target("rare@x.com", "email", interval_hours=1000)
    due = manager.get_due_targets()
    assert len(due) == 2  # both un-scanned

    now = datetime.now(timezone.utc)

    # Create a fresh manager so we start clean
    mgr2 = WatchlistManager(storage_dir=manager._storage_dir)

    mgr2.mark_scanned("frequent@x.com", at=now - timedelta(hours=2))
    mgr2.mark_scanned("rare@x.com", at=now - timedelta(hours=2))

    due = mgr2.get_due_targets(now=now)
    # frequent has interval=1, elapsed 2 -> due
    # rare has interval=1000, elapsed 2 -> not due
    assert len(due) == 1
    assert due[0].target == "frequent@x.com"


def test_get_due_targets_none_due(manager: WatchlistManager):
    manager.add_target("x@y.com", "email", interval_hours=24)
    mgr2 = WatchlistManager(storage_dir=manager._storage_dir)
    now = datetime.now(timezone.utc)
    mgr2.mark_scanned("x@y.com", at=now)
    due = mgr2.get_due_targets(now=now)
    assert due == []


def test_get_due_targets_empty_watchlist(manager: WatchlistManager):
    assert manager.get_due_targets() == []


# ------------------------------------------------------------------
# mark_scanned
# ------------------------------------------------------------------


def test_mark_scanned_updates_timestamp(manager: WatchlistManager):
    manager.add_target("x@y.com", "email")
    now = datetime.now(timezone.utc)
    manager.mark_scanned("x@y.com", at=now)
    obj = manager.get_target("x@y.com")
    assert obj is not None
    assert obj.last_scan == now


def test_mark_scanned_nonexistent(manager: WatchlistManager):
    """Should not raise for a missing target."""
    manager.mark_scanned("ghost@x.com")
    # no exception means success


def test_mark_scanned_default_now(manager: WatchlistManager):
    manager.add_target("x@y.com", "email")
    before = datetime.now(timezone.utc)
    manager.mark_scanned("x@y.com")
    after = datetime.now(timezone.utc)
    obj = manager.get_target("x@y.com")
    assert obj is not None
    assert obj.last_scan is not None
    assert before <= obj.last_scan <= after


# ------------------------------------------------------------------
# count / clear
# ------------------------------------------------------------------


def test_count(populated_manager: WatchlistManager):
    assert populated_manager.count() == 3


def test_count_empty(manager: WatchlistManager):
    assert manager.count() == 0


def test_clear(populated_manager: WatchlistManager):
    assert populated_manager.clear() == 3
    assert populated_manager.count() == 0


def test_clear_empty(manager: WatchlistManager):
    assert manager.clear() == 0


# ------------------------------------------------------------------
# Persistence (survives re-creation of manager)
# ------------------------------------------------------------------


def test_persistence_add_then_reload(tmp_storage: Path):
    mgr1 = WatchlistManager(storage_dir=tmp_storage)
    mgr1.add_target("persist@example.com", "email", tags=["p1"])
    mgr1.add_target("persist2@example.com", "domain", tags=["p2"])

    mgr2 = WatchlistManager(storage_dir=tmp_storage)
    assert mgr2.count() == 2
    assert mgr2.get_target("persist@example.com") is not None
    assert mgr2.get_target("persist2@example.com") is not None


def test_persistence_remove_then_reload(tmp_storage: Path):
    mgr1 = WatchlistManager(storage_dir=tmp_storage)
    mgr1.add_target("gone@example.com", "email")
    mgr1.add_target("stay@example.com", "email")
    mgr1.remove_target("gone@example.com")

    mgr2 = WatchlistManager(storage_dir=tmp_storage)
    assert mgr2.count() == 1
    assert mgr2.get_target("stay@example.com") is not None
    assert mgr2.get_target("gone@example.com") is None


def test_persistence_clear_then_reload(tmp_storage: Path):
    mgr1 = WatchlistManager(storage_dir=tmp_storage)
    mgr1.add_target("x@y.com", "email")
    mgr1.clear()

    mgr2 = WatchlistManager(storage_dir=tmp_storage)
    assert mgr2.count() == 0


def test_persistence_mark_scanned_survives(tmp_storage: Path):
    mgr1 = WatchlistManager(storage_dir=tmp_storage)
    mgr1.add_target("x@y.com", "email")
    ts = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    mgr1.mark_scanned("x@y.com", at=ts)

    mgr2 = WatchlistManager(storage_dir=tmp_storage)
    obj = mgr2.get_target("x@y.com")
    assert obj is not None
    assert obj.last_scan == ts


# ------------------------------------------------------------------
# Corrupt index
# ------------------------------------------------------------------


def test_corrupt_index_starts_fresh(tmp_storage: Path):
    idx = tmp_storage / "index.json"
    tmp_storage.mkdir(parents=True, exist_ok=True)
    idx.write_text("not valid json", encoding="utf-8")

    mgr = WatchlistManager(storage_dir=tmp_storage)
    assert mgr.count() == 0
    mgr.add_target("fresh@x.com", "email")
    assert mgr.count() == 1
