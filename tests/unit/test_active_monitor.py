"""Unit tests for ActiveMonitorDaemon threat intel monitor."""

import pytest

from src.modules.node.active_monitor import ActiveMonitorDaemon


def test_watchlist_hashing():
    daemon = ActiveMonitorDaemon(zkit_salt="test-salt")
    h = daemon.add_to_watchlist("target@example.com")
    assert len(h) == 64
    assert h in daemon.watchlist


@pytest.mark.asyncio
async def test_process_message_with_hits():
    daemon = ActiveMonitorDaemon(zkit_salt="test-salt")

    # Add targets to watchlist
    email_hash = daemon.add_to_watchlist("attacker@threat.org")
    phone_hash = daemon.add_to_watchlist("+15551234567")
    key_hash = daemon.add_to_watchlist("0xabc1230000000000000000000000000000000000000000000000000000001234")

    # Raw message to process
    msg = (
        "Leaked info dump: email attacker@threat.org, "
        "phone +15551234567, EVM key 0xabc1230000000000000000000000000000000000000000000000000000001234. "
        "Unrelated email non_target@example.com."
    )

    hits = await daemon.process_raw_message(msg, source="Telegram_ThreatFeed")

    assert len(hits) == 3
    types = {h["type"] for h in hits}
    assert "email" in types
    assert "phone" in types
    assert "private_key" in types

    # Check findings log
    assert len(daemon.findings_log) == 3
    assert daemon.findings_log[0]["source"] == "Telegram_ThreatFeed"
    assert daemon.findings_log[0]["zkit_hash"] in (email_hash, phone_hash, key_hash)


@pytest.mark.asyncio
async def test_daemon_lifecycle():
    daemon = ActiveMonitorDaemon(zkit_salt="test-salt")
    await daemon.start()
    assert daemon.is_running is True
    assert len(daemon._tasks) == 2

    # Stop daemon
    await daemon.stop()
    assert daemon.is_running is False
    assert len(daemon._tasks) == 0
