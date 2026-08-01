"""Tests for wiring keyless RE/SCRAPE/API sources into the deep scan engine.

P4 gap: threatfox/feodo/malwarebazaar/blockchair/cargo/npm/pypi/rubygems/
mastodon/reddit/stackoverflow/codeberg/social/s3/rss/twitter/telegram/paste/
duckduckgo (keyless RE/SCRAPE) and discord/darknet/dnsdumpster/etherscan/
ipinfo/pulsedive/github (keyless SCRAPE/keyless-API) were all registered in the
transport registry as keyless-capable with real source classes, but were NOT in
the deep scan engine's module config, so the engine never exercised them
through the source_adapter path (consent/RBAC/ToS gates + audit records).
pandi_whois_intel/data_go_id_intel were similarly registered in the free-intel
dispatch but absent from MODULE_INPUTS.

Design contract under test:
- Every wired name resolves to a real source class via discover_sources().
- Every wired name is keyless-capable (RE/SCRAPE/API key_optional).
- 0-API mode (no_api) keeps them and orders RE before SCRAPE before keyless API.
- Free-intel additions (pandi/data_go) route through the free-intel dispatch.

All tests are mocked — no live network calls (repo convention).
"""

from unittest.mock import AsyncMock

import pytest
from pytest import MonkeyPatch

from src.modules.deep_scan import IdentifierType

KEYLESS_SOURCES = {
    # RE / public endpoints
    "threatfox",
    "feodo",
    "malwarebazaar",
    "blockchair",
    "cargo",
    "npm",
    "pypi",
    "rubygems",
    "mastodon",
    "reddit",
    "stackoverflow",
    "codeberg",
    "social",
    "s3",
    "rss",
    "twitter",
    "telegram",
    # SCRAPE
    "paste",
    "duckduckgo",
    "discord",
    "darknet",
    "dnsdumpster",
    # keyless API (key_optional / keyless_fallback)
    "etherscan",
    "ipinfo",
    "pulsedive",
    "github",
}

FREE_INTEL_ADDITIONS = {
    "pandi_whois_intel",
    "data_go_id_intel",
}


def _fake_leak(text: str = "keyless hit: https://example.org/hit"):
    return type(
        "RL",
        (),
        {
            "text": text,
            "source_url": "https://example.org/hit",
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
    def test_module_config_includes_all_keyless_sources(self):
        from src.modules.deep_scan._module_config import MODULE_INPUTS, SOURCE_MODULES

        for name in KEYLESS_SOURCES:
            assert name in SOURCE_MODULES
            assert name in MODULE_INPUTS
        for name in FREE_INTEL_ADDITIONS:
            assert name in MODULE_INPUTS
            assert name not in SOURCE_MODULES  # routed via free-intel dispatch

        # Identifier-type contracts
        assert MODULE_INPUTS["threatfox"] == {IdentifierType.DOMAIN, IdentifierType.IP}
        assert MODULE_INPUTS["feodo"] == {IdentifierType.IP}
        assert MODULE_INPUTS["malwarebazaar"] == {IdentifierType.HASH}
        assert MODULE_INPUTS["blockchair"] == {IdentifierType.CRYPTO_ADDRESS}
        assert MODULE_INPUTS["etherscan"] == {IdentifierType.CRYPTO_ADDRESS}
        assert MODULE_INPUTS["github"] == {
            IdentifierType.USERNAME,
            IdentifierType.EMAIL,
            IdentifierType.DOMAIN,
        }
        assert MODULE_INPUTS["pandi_whois_intel"] == {IdentifierType.DOMAIN}
        assert MODULE_INPUTS["data_go_id_intel"] == {IdentifierType.NAME}

    def test_keyless_sources_auto_discovered_by_sources_package(self):
        """Engine resolves source classes via discover_sources()."""
        from src.modules.sources import discover_sources

        source_map = discover_sources()
        for name in KEYLESS_SOURCES:
            assert name in source_map, f"{name} missing from discover_sources()"
            cls = source_map[name]
            assert hasattr(cls, "search_for_address")
            assert hasattr(cls, "fetch_raw_leaks")

    def test_engine_sees_keyless_sources_as_source_modules(self):
        from src.modules.deep_scan.engine import _SOURCE_MODULES

        for name in KEYLESS_SOURCES:
            assert name in _SOURCE_MODULES

    def test_keyless_sources_are_keyless_capable(self):
        from src.core.source_registry import can_run_keyless, transport_priority

        for name in KEYLESS_SOURCES:
            assert can_run_keyless(name), f"{name} must be keyless-capable"
        for name in FREE_INTEL_ADDITIONS:
            assert can_run_keyless(name), f"{name} must be keyless-capable"

        # RE(0) < SCRAPE(1) < keyless API(2)
        assert transport_priority("threatfox") < transport_priority("duckduckgo")
        assert transport_priority("duckduckgo") < transport_priority("github")
        assert transport_priority("etherscan") < transport_priority("dehashed")

    def test_free_intel_additions_have_dispatch_handlers(self):
        from src.modules.deep_scan.free_intel_adapter import _FREE_INTEL_DISPATCH

        for name in FREE_INTEL_ADDITIONS:
            assert name in _FREE_INTEL_DISPATCH, f"{name} missing dispatch entry"
            label, mod_name, handler = _FREE_INTEL_DISPATCH[name]
            assert callable(handler)
            assert mod_name == name

    def test_no_api_mode_keeps_keyless_sources_ordered_by_tier(self):
        """0-API mode keeps all keyless sources; RE precedes SCRAPE precedes keyless API."""
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(no_api=True)
        mods = engine._get_active_modules()
        for name in KEYLESS_SOURCES | FREE_INTEL_ADDITIONS:
            assert name in mods
        assert mods.index("threatfox") < mods.index("duckduckgo")
        assert mods.index("duckduckgo") < mods.index("github")


class TestKeylessSourceAdapter:
    @pytest.mark.asyncio
    async def test_run_source_scan_keyless_success(self):
        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = [_fake_leak()]
        result = await run_source_scan("threatfox", "example.com", source, requester="test-requester")
        assert result is not None
        assert result.module == "source_threatfox"
        assert result.target == "example.com"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.raw_data["source"] == "threatfox"
        assert finding.confidence == 0.5
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "ok"
        assert entries[0]["requester"] == "test-requester"

    @pytest.mark.asyncio
    async def test_github_source_keyless_json_success(self, monkeypatch: MonkeyPatch):
        """Keyless GitHub REST scan parses RawLeak hits without any token."""
        from src.core.compliance import read_audit_entries
        from src.modules.deep_scan.source_adapter import run_source_scan
        from src.modules.sources.github_source import GitHubLeakSource

        class _FakeResponse:
            status_code = 200
            text = "api_key: abc123\\nemail: alice@example.com"

            def json(self):
                return {
                    "items": [
                        {
                            "full_name": "octocat/Hello-World",
                            "html_url": "https://github.com/octocat/Hello-World",
                            "description": "demo repo",
                        }
                    ]
                }

            def raise_for_status(self):
                return None

        class _FakeClient:
            def __init__(self, *_args, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def get(self, *_args, **_kwargs):
                return _FakeResponse()

        monkeypatch.setattr(
            "src.modules.sources.github_source.httpx.AsyncClient",
            _FakeClient,
        )
        source = GitHubLeakSource()
        result = await run_source_scan("github", "alice", source)
        assert result is not None
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.raw_data["source"] == "github"
        entries = read_audit_entries()
        assert entries[0]["outcome"] == "ok"
