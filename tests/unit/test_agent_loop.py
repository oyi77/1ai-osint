"""Tests for the thin agent loop (blueprint Phase 1 — S4)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.core.models import Finding, ScanResult, Severity
from src.modules.deep_scan.agent_loop import (
    AgentScanPlanner,
    AgentScanReport,
    detect_target_type,
    run_agent_scan,
)


def _fake_scan(n_findings: int = 2) -> ScanResult:
    return ScanResult(
        scan_id="agent-test",
        module="source_hibp",
        target="a@b.com",
        findings=[
            Finding(
                id=f"f{i}",
                module="source_hibp",
                title=f"finding {i}",
                severity=Severity.INFO,
                raw_data={"email": "a@b.com"},
            )
            for i in range(n_findings)
        ],
    )


class TestDetectTargetType:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("user@example.com", "email"),
            ("+62 812-3456-7890", "phone"),
            ("08123456789", "phone"),
            ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "crypto_address"),
            ("example.com", "domain"),
            ("sub.example.co.id", "domain"),
            ("john_doe42", "username"),
            ("Budi Santoso", "name"),
            ("", "unknown"),
        ],
    )
    def test_detection(self, value, expected):
        assert detect_target_type(value) == expected


class TestPlanner:
    def test_plan_orders_sources_by_type(self):
        planner = AgentScanPlanner()
        report = planner.plan("user@example.com")
        assert isinstance(report, AgentScanReport)
        assert report.target_type == "email"
        # First source should be hibp (primary for email)
        assert report.steps[0].source == "hibp"
        assert report.steps[0].kind in ("source", "free")

    def test_plan_unknown_type_still_has_fallback_breach_sources(self):
        planner = AgentScanPlanner()
        report = planner.plan("0x1234")
        # crypto has no plan — fallback breach sources should be added
        assert len(report.steps) >= 1

    def test_consent_required_sources_blocked_by_default(self):
        planner = AgentScanPlanner()
        report = planner.plan("user@example.com")
        for step in report.steps:
            if step.skipped:
                assert "consent" in step.reason.lower()
        # Blocked list populated
        for blocked in report.blocked_sources:
            assert any(s.source == blocked and s.skipped for s in report.steps)


class TestAgentLoopExecution:
    @pytest.mark.asyncio
    async def test_run_collects_findings(self):
        planner = AgentScanPlanner()
        with (
            patch("src.modules.deep_scan.agent_loop.run_source_scan", new=AsyncMock(return_value=_fake_scan(3))),
            patch("src.modules.deep_scan.agent_loop.run_free_intel_scan", new=AsyncMock(return_value=_fake_scan(1))),
        ):
            report = await planner.run("user@example.com", max_sources=6)
        assert report.total_findings >= 0
        assert report.duration_ms >= 0
        assert any(s.attempted for s in report.steps)

    @pytest.mark.asyncio
    async def test_rate_limited_source_falls_back_to_alternate(self):
        planner = AgentScanPlanner()

        # hibp raises rate-limit; intelx (alternate) succeeds
        def fake_run_hibp(*args, **kwargs):
            raise RuntimeError("Rate limit exceeded (429)")

        with (
            patch(
                "src.modules.deep_scan.agent_loop.run_source_scan",
                new=AsyncMock(side_effect=fake_run_hibp),
            ),
            patch("src.modules.deep_scan.agent_loop.run_free_intel_scan", new=AsyncMock(return_value=_fake_scan(2))),
        ):
            report = await planner.run("user@example.com", max_sources=10)
        # hibp should be marked failed with rate-limit reason
        hibp_step = next(s for s in report.steps if s.source == "hibp")
        assert hibp_step.attempted
        assert "rate" in hibp_step.reason.lower()
        # Free-intel alternates should have been attempted (fallback wave)
        assert any(s.attempted and s.ok for s in report.steps[3:])

    @pytest.mark.asyncio
    async def test_error_source_does_not_crash_scan(self):
        planner = AgentScanPlanner()
        with (
            patch(
                "src.modules.deep_scan.agent_loop.run_source_scan",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch("src.modules.deep_scan.agent_loop.run_free_intel_scan", new=AsyncMock(return_value=_fake_scan(1))),
        ):
            report = await planner.run("user@example.com", max_sources=6)
        # No exception propagates; steps recorded as failed
        assert any(s.attempted and not s.ok for s in report.steps)

    @pytest.mark.asyncio
    async def test_run_agent_scan_wrapper(self):
        with (
            patch("src.modules.deep_scan.agent_loop.run_source_scan", new=AsyncMock(return_value=_fake_scan(2))),
            patch("src.modules.deep_scan.agent_loop.run_free_intel_scan", new=AsyncMock(return_value=_fake_scan(1))),
        ):
            report = await run_agent_scan("user@example.com")
        assert report.target == "user@example.com"
        assert "email" == report.target_type

    @pytest.mark.asyncio
    async def test_consent_gate_skips_source_without_query(self):
        planner = AgentScanPlanner()
        with (
            patch("src.modules.deep_scan.agent_loop.run_source_scan", new=AsyncMock(return_value=_fake_scan(1))),
            patch("src.modules.deep_scan.agent_loop.run_free_intel_scan", new=AsyncMock(return_value=_fake_scan(1))),
        ):
            report = await planner.run(
                "user@example.com",
                max_sources=6,
                allow_consent_required=False,
            )
        # Consent-required steps must not be attempted
        for step in report.steps:
            if step.skipped:
                assert not step.attempted
