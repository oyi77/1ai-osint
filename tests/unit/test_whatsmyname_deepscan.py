"""Tests for wiring the keyless whatsmyname username source into deep scan.

Covers the P2 gap: whatsmyname was already a registered scrape source and
had unit tests, but was NOT in the deep scan engine's module config, so it
was never exercised in-process during a scan.

All tests are mocked — no live network calls (repo convention).

Note (documented honesty): whatsmyName's web search page echoes the query
back in the page, so the source adapter's presence check is a weak heuristic
("presence-echo") rather than a real cross-site hit confirmation. We keep the
source wired for breadth, and flag the limitation in BREADTH_AUDIT.md.
"""

import pytest
from pytest import MonkeyPatch

from src.modules.deep_scan import IdentifierType


def _fake_leak(text: str = "Username 'alice' found on WhatsMyName results page"):
    return type(
        "RL",
        (),
        {
            "text": text,
            "source_url": "https://whatsmyname.com/search?q=alice",
        },
    )()


@pytest.fixture(autouse=True)
def _isolate_audit_path(tmp_path, monkeypatch: MonkeyPatch):
    monkeypatch.setattr(
        "src.core.compliance.settings.audit_log_path",
        str(tmp_path / "audit.jsonl"),
    )
    yield


class TestDeepScanWiring:
    def test_module_config_includes_whatsmyname(self):
        from src.modules.deep_scan._module_config import MODULE_INPUTS, SOURCE_MODULES

        assert "whatsmyname" in SOURCE_MODULES
        assert IdentifierType.USERNAME in MODULE_INPUTS["whatsmyname"]

    def test_whatsmyname_auto_discovered_by_sources_package(self):
        """The deep scan engine resolves source classes via discover_sources()."""
        from src.modules.sources import discover_sources

        source_map = discover_sources()
        assert "whatsmyname" in source_map
        cls = source_map["whatsmyname"]
        assert hasattr(cls, "search_for_address")
        assert hasattr(cls, "fetch_raw_leaks")

    def test_engine_sees_whatsmyname_as_source_module(self):
        from src.modules.deep_scan.engine import _SOURCE_MODULES

        assert "whatsmyname" in _SOURCE_MODULES


class TestSourceAdapterWiring:
    @pytest.mark.asyncio
    async def test_run_source_scan_success(self):
        from unittest.mock import AsyncMock

        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = [_fake_leak()]
        result = await run_source_scan("whatsmyname", "alice", source, requester="test-requester")
        assert result is not None
        assert result.module == "source_whatsmyname"
        assert result.target == "alice"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.raw_data["source"] == "whatsmyname"
        # Not a structured source -> generic confidence.
        assert finding.confidence == 0.5
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "ok"
        assert entries[0]["requester"] == "test-requester"

    @pytest.mark.asyncio
    async def test_run_source_scan_empty_records_empty_audit(self):
        from unittest.mock import AsyncMock

        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = []
        result = await run_source_scan("whatsmyname", "alice", source)
        assert result is None
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "empty"

    @pytest.mark.asyncio
    async def test_run_source_scan_error_never_raises(self):
        from unittest.mock import AsyncMock

        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.side_effect = RuntimeError("boom")
        result = await run_source_scan("whatsmyname", "alice", source)
        assert result is None
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "error"
