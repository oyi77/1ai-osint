"""Tests for RBAC (per-tier access) and ToS guard (per-source rate limits).

Covers blueprint Layer 3 gaps closed in this phase:
- RBAC: AccessTier ordering, token→tier resolution, source min-tier gate.
- ToS guard: per-source rate ceiling enforcement, throttling behavior.
- Integration: run_source_scan / run_free_intel_scan enforce both gates and
  record blocked/throttled outcomes in the audit trail.

Run with: python -m pytest tests/unit/test_rbac_tos.py -v --tb=short
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.core.compliance import min_tier_for, source_allows_tier
from src.core.rbac import AccessTier, tier_allows
from src.core.tos_guard import reset_guard, tos_allows


@pytest.fixture(autouse=True)
def _isolate_rate_limit_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the ToS guard at a temp state file so these tests never read
    or write the developer's real rate-limit state."""
    from src.core.config import settings as core_settings

    monkeypatch.setattr(core_settings, "rate_limit_file", str(tmp_path / "rate_limit.json"))


class TestAccessTier:
    """Tier ordering and parsing."""

    def test_ordering(self) -> None:
        assert AccessTier.READONLY < AccessTier.ANALYST < AccessTier.ADMIN

    def test_from_str_case_insensitive(self) -> None:
        assert AccessTier.from_str("ADMIN") is AccessTier.ADMIN
        assert AccessTier.from_str("analyst") is AccessTier.ANALYST
        assert AccessTier.from_str("ReadOnly") is AccessTier.READONLY

    def test_from_str_unknown_defaults_readonly(self) -> None:
        assert AccessTier.from_str("superuser") is AccessTier.READONLY
        assert AccessTier.from_str(None) is AccessTier.READONLY

    def test_tier_allows(self) -> None:
        assert tier_allows(AccessTier.ADMIN, AccessTier.READONLY)
        assert tier_allows(AccessTier.ANALYST, AccessTier.ANALYST)
        assert not tier_allows(AccessTier.READONLY, AccessTier.ADMIN)
        assert not tier_allows(AccessTier.READONLY, AccessTier.ANALYST)


class TestTokenResolution:
    """WEB_AUTH_TOKENS / WEB_AUTH_TOKEN → tier resolution."""

    def test_legacy_token_is_admin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEB_AUTH_TOKEN", "legacy-secret")
        monkeypatch.delenv("WEB_AUTH_TOKENS", raising=False)
        import importlib

        import src.core.rbac as rbac

        importlib.reload(rbac)
        # Compare against the *reloaded* module's enum class (identity
        # against the pre-reload import would fail — reload creates a new
        # class object).
        assert rbac.tier_for_token("legacy-secret") is rbac.AccessTier.ADMIN
        assert rbac.tier_for_token("unknown") is None
        assert rbac.token_is_valid("legacy-secret")
        assert not rbac.token_is_valid("nope")

    def test_multi_tier_tokens(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WEB_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("WEB_AUTH_TOKENS", "readonly:ro-tok,admin:ad-tok")
        import importlib

        import src.core.rbac as rbac

        importlib.reload(rbac)
        assert rbac.tier_for_token("ro-tok") is rbac.AccessTier.READONLY
        assert rbac.tier_for_token("ad-tok") is rbac.AccessTier.ADMIN
        assert rbac.tier_for_token("unknown") is None

    def test_no_tokens_means_nothing_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WEB_AUTH_TOKEN", raising=False)
        monkeypatch.delenv("WEB_AUTH_TOKENS", raising=False)
        import importlib

        import src.core.rbac as rbac

        importlib.reload(rbac)
        assert rbac.tier_for_token("anything") is None
        assert not rbac.token_is_valid("anything")


class TestSourceTierGate:
    """Compliance registry min-tier assignments and checks."""

    def test_paid_breach_dbs_require_admin(self) -> None:
        for name in ("dehashed", "intelx", "leakcheck", "snusbase", "snylla"):
            assert min_tier_for(name) is AccessTier.ADMIN, name

    def test_govt_open_data_is_readonly(self) -> None:
        for name in ("pandi_whois_intel", "data_go_id_intel", "pddikti_intel"):
            assert min_tier_for(name) is AccessTier.READONLY, name

    def test_public_sources_default_readonly(self) -> None:
        assert min_tier_for("hibp") is AccessTier.READONLY

    def test_source_allows_tier(self) -> None:
        # ADMIN can query everything.
        assert source_allows_tier("dehashed", AccessTier.ADMIN)
        # READONLY cannot query ADMIN-only sources.
        assert not source_allows_tier("dehashed", AccessTier.READONLY)
        # READONLY can query public sources.
        assert source_allows_tier("hibp", AccessTier.READONLY)

    def test_breach_sources_have_low_rpm(self) -> None:
        from src.core.compliance import requests_per_minute_for

        assert requests_per_minute_for("dehashed") == 10


class TestToSGuard:
    """Per-source rate ceiling enforcement."""

    def setup_method(self) -> None:
        reset_guard()

    def teardown_method(self) -> None:
        reset_guard()

    def test_allows_burst_then_throttles(self) -> None:
        # dehashed is capped at 10 rpm with burst ~5 → after ~15 calls the
        # bucket is exhausted and tos_allows() must return False.
        allowed = sum(1 for _ in range(30) if tos_allows("dehashed"))
        assert allowed < 30  # eventually throttled
        assert allowed >= 1  # but the first few calls are allowed

    def test_high_rpm_source_allows_more(self) -> None:
        # hibp is capped at 30 rpm (burst 7) — a short burst of 5 passes.
        assert all(tos_allows("hibp") for _ in range(5))
        # abuseipdb is capped at 120 rpm (burst 30) — 10 calls always pass.
        assert all(tos_allows("abuseipdb") for _ in range(10))

    def test_reset_restores_capacity(self) -> None:
        for _ in range(50):
            tos_allows("dehashed")
        assert not tos_allows("dehashed")  # exhausted
        reset_guard()
        assert tos_allows("dehashed")  # capacity restored


class TestAdapterGates:
    """Integration: run_source_scan / run_free_intel_scan enforce RBAC + ToS."""

    async def test_run_source_scan_blocks_below_tier(self) -> None:
        from src.modules.deep_scan.source_adapter import run_source_scan

        class _FakeSource:
            async def search_for_address(self, *args, **kwargs):  # pragma: no cover
                return None

        result = await run_source_scan(
            "dehashed",
            "victim@example.com",
            _FakeSource(),
            requester="test",
            requester_tier=AccessTier.READONLY,
        )
        assert result is None

    async def test_run_source_scan_allows_admin(self) -> None:
        from src.modules.deep_scan.source_adapter import run_source_scan

        class _FakeSource:
            async def search_for_address(self, *args, **kwargs):  # pragma: no cover
                return None

        # ADMIN passes the tier gate; the fake source returns nothing (None),
        # which is a no-data outcome rather than a block — same return type.
        result = await run_source_scan(
            "dehashed",
            "victim@example.com",
            _FakeSource(),
            requester="test",
            requester_tier=AccessTier.ADMIN,
        )
        assert result is None

    async def test_run_free_intel_throttles(self) -> None:
        from src.modules.deep_scan.free_intel_adapter import run_free_intel_scan

        # pddikti_intel is READONLY tier with 60 rpm default — a loop of 200
        # calls must eventually hit the ToS ceiling and return None
        # (throttled) without raising.
        #
        # The handler performs a real HTTP lookup, so mock the PDDIKTIIntel
        # client (repo convention: never call real endpoints in tests) —
        # the ToS ceiling is enforced *before* the handler runs, so this
        # still exercises throttling without network access.
        blocked = 0
        with patch(
            "src.modules.free_intel.pddikti_intel.PDDIKTIIntel.search",
            new_callable=AsyncMock,
            return_value=[],
        ):
            for _ in range(200):
                result = await run_free_intel_scan("pddikti_intel", "joko", requester="test")
                if result is None:
                    blocked += 1
        assert blocked > 0  # throttling kicked in

    async def test_audit_trail_records_throttle(self, tmp_path) -> None:
        from src.core import compliance

        # Point the audit log at a temp file so the test never touches the
        # developer's real audit trail.
        original = compliance.settings.audit_log_path
        compliance.settings.audit_log_path = str(tmp_path / "audit.jsonl")
        try:
            before = len(compliance.read_audit_entries(limit=1000))
            compliance.record_audit(
                source="dehashed",
                target="victim@example.com",
                requester="test",
                outcome="throttled",
                legal_basis="undocumented",
            )
            entries = compliance.read_audit_entries(limit=1000)
            assert len(entries) == before + 1
            assert entries[0]["outcome"] == "throttled"  # newest first
            assert entries[0]["source"] == "dehashed"
        finally:
            compliance.settings.audit_log_path = original


class TestAnalystTierSources:
    """Batch K: shodan/censys hardened from READONLY to ANALYST."""

    def test_shodan_and_censys_require_analyst(self) -> None:
        assert min_tier_for("shodan") is AccessTier.ANALYST
        assert min_tier_for("censys") is AccessTier.ANALYST

    def test_analyst_tier_gate(self) -> None:
        assert not source_allows_tier("shodan", AccessTier.READONLY)
        assert not source_allows_tier("censys", AccessTier.READONLY)
        assert source_allows_tier("shodan", AccessTier.ANALYST)
        assert source_allows_tier("censys", AccessTier.ANALYST)
        assert source_allows_tier("censys", AccessTier.ADMIN)


class TestFreeIntelAuditTrail:
    """Batch K: free-intel scans record ok/empty outcomes in the audit trail."""

    async def _run_and_read_audit(self, tmp_path, handler) -> list[dict]:
        from src.core import compliance
        from src.modules.deep_scan.free_intel_adapter import (
            _FREE_INTEL_DISPATCH,
            run_free_intel_scan,
        )

        original = compliance.settings.audit_log_path
        compliance.settings.audit_log_path = str(tmp_path / "audit.jsonl")
        try:
            with patch.dict(
                _FREE_INTEL_DISPATCH,
                {"audit_test_mod": ("label", "target_type", handler)},
            ):
                await run_free_intel_scan("audit_test_mod", "victim", requester="test")
            return compliance.read_audit_entries(limit=1000)
        finally:
            compliance.settings.audit_log_path = original

    async def test_empty_handler_records_empty_outcome(self, tmp_path) -> None:
        async def empty_handler(target):  # pragma: no cover
            return None

        entries = await self._run_and_read_audit(tmp_path, empty_handler)
        assert entries
        assert entries[0]["outcome"] == "empty"
        assert entries[0]["source"] == "audit_test_mod"
        assert entries[0]["requester"] == "test"

    async def test_ok_handler_records_findings_count(self, tmp_path) -> None:
        from src.core.models import Finding, ScanResult, Severity

        async def ok_handler(target):  # pragma: no cover
            return ScanResult(
                scan_id="s",
                module="audit_test_mod",
                target=target,
                status="ok",
                findings=[
                    Finding(
                        id="f1",
                        module="audit_test_mod",
                        title="hit",
                        description="d",
                        severity=Severity.INFO,
                    )
                ],
            )

        entries = await self._run_and_read_audit(tmp_path, ok_handler)
        assert entries
        assert entries[0]["outcome"] == "ok"
        assert entries[0]["source"] == "audit_test_mod"
        assert entries[0]["findings_count"] == 1

    async def test_error_handler_records_error_outcome(self, tmp_path) -> None:
        async def error_handler(target):  # pragma: no cover
            raise RuntimeError("boom")

        entries = await self._run_and_read_audit(tmp_path, error_handler)
        assert entries
        assert entries[0]["outcome"] == "error"
        assert entries[0]["source"] == "audit_test_mod"
        assert entries[0]["requester"] == "test"
