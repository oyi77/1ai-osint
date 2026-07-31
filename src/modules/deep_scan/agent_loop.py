"""Thin agent loop for deep scan (blueprint Phase 1 — S4).

One input → rule-based planner picks the relevant adapters → runs them
with fallback on rate-limit/error → returns a structured report.

Design notes (blueprint S4):
- No LLM in the loop: the planner is deterministic (target-type → modules).
- Fallback: if a primary source fails or rate-limits, the next
  alternate of the same target type is tried.
- Compliance gate: consent-required sources (UU PDP Pasal 4.2) are
  skipped unless explicitly permitted.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from src.core.compliance import get_compliance
from src.core.rbac import AccessTier
from src.modules.deep_scan.free_intel_adapter import list_free_intel_modules, run_free_intel_scan
from src.modules.deep_scan.source_adapter import run_source_scan
from src.modules.sources import discover_sources

logger = logging.getLogger(__name__)

# Target-type → ordered source candidates (primary first, alternates after).
# Breach adapters are keyed by their registered source name; free intel
# modules by their module key.
_TYPE_PLAN: dict[str, list[str]] = {
    "email": [
        "hibp",
        "intelx",
        "leakcheck",
        "snylla",
        "snusbase",
        "dehashed",
        "hibp_free",
        "gravatar_intel",
    ],
    "username": [
        "intelx",
        "leakcheck",
        "snylla",
        "snusbase",
        "dehashed",
        "github_intel",
        "telegram_check",
    ],
    "phone": [
        "intelx",
        "snylla",
        "snusbase",
        "dehashed",
        "bts_intel",
        "whatsapp_check",
    ],
    "domain": [
        "pandi_whois_intel",
        "intelx",
        "snylla",
        "dehashed",
        "leakcheck",
        "wayback_intel",
    ],
    "name": [
        "social_dorks_intel",
        "google_dork_intel",
        "pddikti_intel",
        "data_go_id_intel",
        "tech_jobs_intel",
        "intelx",
    ],
    "crypto_address": [],
}

# Fallback order when a primary source is unavailable (no key) or fails.
_FALLBACK_ORDER: dict[str, list[str]] = {
    "breach": [
        "hibp",
        "intelx",
        "leakcheck",
        "snylla",
        "snusbase",
        "dehashed",
    ],
    "free": [
        "hibp_free",
        "gravatar_intel",
        "github_intel",
        "telegram_check",
        "bts_intel",
        "whatsapp_check",
        "wayback_intel",
        "social_dorks_intel",
        "google_dork_intel",
        "pddikti_intel",
        "tech_jobs_intel",
    ],
}

_RATE_LIMIT_PATTERNS = re.compile(
    r"rate.?limit|429|too many requests|quota|throttl",
    re.IGNORECASE,
)


@dataclass
class AgentScanStep:
    """One planned (or attempted) source step."""

    source: str
    kind: str  # "source" | "free"
    attempted: bool = False
    ok: bool = False
    skipped: bool = False
    reason: str = ""
    findings: int = 0
    latency_ms: int = 0


@dataclass
class AgentScanReport:
    """Structured result of a thin-agent scan run."""

    target: str
    target_type: str
    steps: list[AgentScanStep] = field(default_factory=list)
    total_findings: int = 0
    blocked_sources: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "steps": [
                {
                    "source": s.source,
                    "kind": s.kind,
                    "attempted": s.attempted,
                    "ok": s.ok,
                    "skipped": s.skipped,
                    "reason": s.reason,
                    "findings": s.findings,
                    "latency_ms": s.latency_ms,
                }
                for s in self.steps
            ],
            "total_findings": self.total_findings,
            "blocked_sources": self.blocked_sources,
            "duration_ms": self.duration_ms,
        }


def detect_target_type(target: str) -> str:
    """Rule-based identifier type detection (no LLM)."""
    t = target.strip()
    if not t:
        return "unknown"
    if "@" in t and "." in t.split("@")[-1]:
        return "email"
    if re.fullmatch(r"\+?[0-9][0-9 ()-]{6,}", t):
        return "phone"
    if re.fullmatch(r"(0x[0-9a-fA-F]{40})|([1-9A-HJ-NP-Za-km-z]{32,44})", t):
        return "crypto_address"
    if re.fullmatch(r"(?=.{4,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}", t):
        return "domain"
    if re.fullmatch(r"[A-Za-z0-9._-]{3,32}", t):
        return "username"
    if " " in t:
        return "name"
    return "username"


class AgentScanPlanner:
    """Rule-based planner: target → ordered source plan with fallbacks."""

    def __init__(self, settings: Any | None = None) -> None:
        self._sources_map = discover_sources()
        self._free_modules: set[str] = set(list_free_intel_modules())
        self._settings = settings

    # ── planning ──────────────────────────────────────────────────────────

    def _available_kind(self, name: str) -> str | None:
        if name in self._sources_map:
            return "source"
        if name in self._free_modules:
            return "free"
        return None

    def plan(self, target: str, *, allow_consent_required: bool = False) -> AgentScanReport:
        """Build the ordered step plan for a target."""
        target_type = detect_target_type(target)
        report = AgentScanReport(target=target, target_type=target_type)

        primary = _TYPE_PLAN.get(target_type, [])
        planned: list[str] = []
        for name in primary:
            kind = self._available_kind(name)
            if kind is None:
                continue  # not registered in this environment
            planned.append(name)
            report.steps.append(AgentScanStep(source=name, kind=kind))

        # Add any remaining source adapters of the same type as alternates
        if not planned:
            for name in _FALLBACK_ORDER["breach"]:
                kind = self._available_kind(name)
                if kind is None:
                    continue
                planned.append(name)
                report.steps.append(AgentScanStep(source=name, kind=kind))

        # Compliance pre-filter: consent-required sources blocked unless allowed
        blocked: list[str] = []
        for step in report.steps:
            comp = get_compliance(step.source)
            if comp.requires_consent and not allow_consent_required:
                step.skipped = True
                step.reason = "consent-required (UU PDP) — blocked by compliance gate"
                blocked.append(step.source)
        report.blocked_sources = blocked
        return report

    # ── execution ─────────────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        *,
        max_sources: int = 6,
        allow_consent_required: bool = False,
        requester: str = "agent_loop",
        requester_tier: AccessTier = AccessTier.ADMIN,
        timeout_per_source: float = 30.0,
    ) -> AgentScanReport:
        """Execute the plan with fallback on rate-limit/error."""
        report = self.plan(target, allow_consent_required=allow_consent_required)
        started = time.monotonic()

        runnable = [s for s in report.steps if not s.skipped][:max_sources]
        if not runnable:
            report.duration_ms = int((time.monotonic() - started) * 1000)
            return report

        # Run primary candidates concurrently; if all fail with rate-limit,
        # try the next alternate batch (simple two-wave fallback).
        primary = runnable[:3]
        alternates = runnable[3:]

        results = await asyncio.gather(
            *(self._run_one(step, target, requester, requester_tier, timeout_per_source) for step in primary),
            return_exceptions=True,
        )
        for step, res in zip(primary, results, strict=False):
            if isinstance(res, BaseException):
                self._record_failure(step, res)
                continue
            step.attempted = True
            step.ok = True
            step.findings = int(res)
            report.total_findings += step.findings

        # Fallback wave: only for sources not yet attempted (rate-limited / errored)
        failed = [s for s in primary if s.attempted and not s.ok]
        if failed and alternates:
            # Run alternates until `len(failed)` of them succeed (or run out).
            still_failed = len(failed)
            fb_batch = alternates[:]
            for batch_start in range(0, len(fb_batch), 3):
                if still_failed <= 0:
                    break
                batch = fb_batch[batch_start : batch_start + 3]
                fb_results = await asyncio.gather(
                    *(self._run_one(step, target, requester, requester_tier, timeout_per_source) for step in batch),
                    return_exceptions=True,
                )
                for step, res in zip(batch, fb_results, strict=False):
                    if isinstance(res, BaseException):
                        self._record_failure(step, res)
                        continue
                    step.attempted = True
                    step.ok = True
                    step.findings = int(res)
                    report.total_findings += step.findings
                    still_failed -= 1

        report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

    async def _run_one(
        self,
        step: AgentScanStep,
        target: str,
        requester: str,
        requester_tier: AccessTier,
        timeout: float,
    ) -> int:
        """Run one planned step, returning finding count (0 on no-data)."""
        started = time.monotonic()
        try:
            if step.kind == "source":
                source_inst = self._sources_map[step.source]()
                scan = await asyncio.wait_for(
                    run_source_scan(
                        step.source,
                        target,
                        source_inst,
                        requester=requester,
                        requester_tier=requester_tier,
                    ),
                    timeout=timeout,
                )
            else:
                scan = await asyncio.wait_for(
                    run_free_intel_scan(
                        step.source,
                        target,
                        requester=requester,
                        requester_tier=requester_tier,
                    ),
                    timeout=timeout,
                )
        except asyncio.TimeoutError as exc:
            step.attempted = True
            step.reason = f"timeout after {timeout:.0f}s"
            step.latency_ms = int((time.monotonic() - started) * 1000)
            raise TimeoutError(step.reason) from exc
        except Exception as exc:
            step.attempted = True
            step.latency_ms = int((time.monotonic() - started) * 1000)
            msg = str(exc)
            step.reason = msg[:200]
            if _RATE_LIMIT_PATTERNS.search(msg):
                step.reason = f"rate-limited: {msg[:120]}"
            raise exc

        step.latency_ms = int((time.monotonic() - started) * 1000)
        if scan is None:
            step.reason = "no data"
            return 0
        return len(scan.findings)

    @staticmethod
    def _record_failure(step: AgentScanStep, exc: BaseException) -> None:
        step.attempted = True
        step.ok = False
        step.reason = str(exc)[:200]


async def run_agent_scan(
    target: str,
    *,
    max_sources: int = 6,
    allow_consent_required: bool = False,
    requester: str = "agent_loop",
    requester_tier: AccessTier = AccessTier.ADMIN,
) -> AgentScanReport:
    """Convenience wrapper: one input → thin-agent scan → structured report."""
    planner = AgentScanPlanner()
    return await planner.run(
        target,
        max_sources=max_sources,
        allow_consent_required=allow_consent_required,
        requester=requester,
        requester_tier=requester_tier,
    )
