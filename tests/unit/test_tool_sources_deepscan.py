"""Tests for wiring keyless TOOL sources into the deep scan engine.

P3 gap: sherlock/maigret/holehe/theharvester/subfinder/amass/bbot/nmap/httpx/
phoneinfoga/h8mail were already registered TOOL transports with subprocess
implementations, but were NOT in the deep scan engine's module config, so the
engine never exercised them through the source_adapter path (consent/RBAC/ToS
gates + audit records).

Design contract under test:
- CLI binary present  -> in-process keyless scan via source_adapter.
- CLI binary missing  -> deterministic empty outcome, audited, never blocks.
- 0-API mode (no_api) -> TOOL sources are keyless-capable, kept, and ordered
  after RE/SCRAPE sources (transport_priority TOOL=4).

All tests are mocked — no live network calls and no real CLI invocations
(repo convention).
"""

import json
from unittest.mock import AsyncMock

import pytest
from pytest import MonkeyPatch

from src.modules.deep_scan import IdentifierType

TOOL_SOURCES = {
    "sherlock",
    "maigret",
    "holehe",
    "theharvester",
    "subfinder",
    "amass",
    "bbot",
    "nmap",
    "httpx",
    "phoneinfoga",
    "h8mail",
}


def _fake_leak(text: str = "Username 'alice' found on GitHub: https://github.com/alice"):
    return type(
        "RL",
        (),
        {
            "text": text,
            "source_url": "https://github.com/alice",
        },
    )()


@pytest.fixture(autouse=True)
def _isolate_audit_path(tmp_path, monkeypatch: MonkeyPatch):
    monkeypatch.setattr(
        "src.core.compliance.settings.audit_log_path",
        str(tmp_path / "audit.jsonl"),
    )
    yield


class TestModuleConfigWiring:
    def test_module_config_includes_all_tool_sources(self):
        from src.modules.deep_scan._module_config import MODULE_INPUTS, SOURCE_MODULES

        for name in TOOL_SOURCES:
            assert name in SOURCE_MODULES
            assert name in MODULE_INPUTS

        assert MODULE_INPUTS["sherlock"] == {IdentifierType.USERNAME}
        assert MODULE_INPUTS["maigret"] == {IdentifierType.USERNAME}
        assert MODULE_INPUTS["holehe"] == {IdentifierType.EMAIL}
        assert MODULE_INPUTS["theharvester"] == {IdentifierType.DOMAIN}
        assert MODULE_INPUTS["subfinder"] == {IdentifierType.DOMAIN}
        assert MODULE_INPUTS["amass"] == {IdentifierType.DOMAIN}
        assert MODULE_INPUTS["bbot"] == {IdentifierType.DOMAIN}
        assert MODULE_INPUTS["nmap"] == {IdentifierType.IP, IdentifierType.DOMAIN}
        assert MODULE_INPUTS["httpx"] == {
            IdentifierType.DOMAIN,
            IdentifierType.IP,
            IdentifierType.URL,
        }
        assert MODULE_INPUTS["phoneinfoga"] == {IdentifierType.PHONE}
        assert MODULE_INPUTS["h8mail"] == {IdentifierType.EMAIL}

    def test_tool_sources_auto_discovered_by_sources_package(self):
        """Engine resolves TOOL source classes via discover_sources()."""
        from src.modules.sources import discover_sources

        source_map = discover_sources()
        for name in TOOL_SOURCES:
            assert name in source_map, f"{name} missing from discover_sources()"
            cls = source_map[name]
            assert hasattr(cls, "search_for_address")
            assert hasattr(cls, "fetch_raw_leaks")

    def test_engine_sees_tool_sources_as_source_modules(self):
        from src.modules.deep_scan.engine import _SOURCE_MODULES

        for name in TOOL_SOURCES:
            assert name in _SOURCE_MODULES

    def test_tool_sources_are_keyless_capable(self):
        from src.core.source_registry import can_run_keyless, transport_priority

        for name in TOOL_SOURCES:
            assert can_run_keyless(name), f"{name} must be keyless-capable"
            # TOOL(4) ordered strictly after RE(0)/SCRAPE(1)
            assert transport_priority("certspotter") < transport_priority(name)
            assert transport_priority("whatsmyname") < transport_priority(name)

    def test_no_api_mode_keeps_tool_sources_after_re(self):
        """0-API mode keeps TOOL sources and orders RE sources before them."""
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(no_api=True)
        mods = engine._get_active_modules()
        for name in TOOL_SOURCES:
            assert name in mods
        # RE source strictly precedes every TOOL source in 0-API ordering.
        assert mods.index("certspotter") < min(mods.index(n) for n in TOOL_SOURCES)


class TestToolSourceAdapter:
    @pytest.mark.asyncio
    async def test_run_source_scan_tool_success(self):
        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = [_fake_leak()]
        result = await run_source_scan("sherlock", "alice", source, requester="test-requester")
        assert result is not None
        assert result.module == "source_sherlock"
        assert result.target == "alice"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.raw_data["source"] == "sherlock"
        # Not a structured source -> generic confidence.
        assert finding.confidence == 0.5
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "ok"
        assert entries[0]["requester"] == "test-requester"

    @pytest.mark.asyncio
    async def test_sherlock_cli_missing_degrades_to_empty(self, monkeypatch: MonkeyPatch):
        """CLI binary missing -> [] from the real source, empty audited outcome."""
        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan
        from src.modules.sources.sherlock_source import SherlockSource

        monkeypatch.setattr(
            "src.modules.sources.sherlock_source.shutil.which",
            lambda _name: None,
        )
        source = SherlockSource()
        leaks = await source.search_for_address("alice")
        assert leaks == []
        result = await run_source_scan("sherlock", "alice", source)
        assert result is None
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "empty"

    @pytest.mark.asyncio
    async def test_sherlock_cli_json_success(self, monkeypatch: MonkeyPatch):
        """Fake sherlock CLI emits JSON -> real source parses RawLeak hits."""
        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan
        from src.modules.sources.sherlock_source import SherlockSource

        async def fake_exec(*args, **_kwargs):
            # args = (path, address, "--print-found", "--json", out_path)
            out_path = args[4]
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "GitHub": {"status": "Claimed", "url": "https://github.com/alice"},
                        "NotClaimed": {"status": "Not claimed", "url": ""},
                    },
                    f,
                )
            proc = AsyncMock()
            proc.communicate.return_value = (b"", b"")
            return proc

        monkeypatch.setattr(
            "src.modules.sources.sherlock_source.shutil.which",
            lambda _name: "/usr/bin/sherlock",
        )
        monkeypatch.setattr(
            "src.modules.sources.sherlock_source.asyncio.create_subprocess_exec",
            fake_exec,
        )
        source = SherlockSource()
        result = await run_source_scan("sherlock", "alice", source)
        assert result is not None
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.raw_data["source"] == "sherlock"
        assert finding.raw_data["source_url"] == "https://github.com/alice"
        entries = read_audit_entries()
        assert entries[0]["outcome"] == "ok"
