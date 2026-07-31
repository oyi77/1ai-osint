#!/usr/bin/env python3
"""Head-to-head benchmark: S4 agent loop vs naive batch scan (blueprint Phase 3).

Measures the value of the thin agent loop (rule-based planner + rate-limit
fallback) against the naive "run every adapter" approach in a controlled,
deterministic environment:

- Some sources are rate-limited (simulated) — the naive batch wastes time
  and accumulates errors; the agent loop pivots to alternates.
- Some sources are slow (simulated latency) — the agent loop's parallel
  primary wave + bounded fallback keeps total time low.

All external calls are mocked. No network access. Deterministic output.

Usage:
    python scripts/benchmark_agent_vs_batch.py
"""

from __future__ import annotations

import asyncio

# Ensure project root is on path
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.modules.deep_scan.agent_loop import AgentScanPlanner, run_agent_scan

# ── Simulated source behaviour ───────────────────────────────────────────────
# source_name -> (kind, latency_s, outcome)
# outcome: "ok" (returns findings), "empty", "rate_limit" (raises), "error"
_SIM_SOURCES: dict[str, tuple[str, float, str]] = {
    "hibp": ("breach", 0.05, "ok"),
    "intelx": ("breach", 0.20, "rate_limit"),
    "leakcheck": ("breach", 0.15, "rate_limit"),
    "snylla": ("breach", 0.10, "ok"),
    "snusbase": ("breach", 0.10, "empty"),
    "dehashed": ("breach", 0.12, "error"),
    "hibp_free": ("free", 0.08, "ok"),
    "gravatar_intel": ("free", 0.06, "ok"),
    "github_intel": ("free", 0.09, "ok"),
    "telegram_check": ("free", 0.07, "empty"),
    "wayback_intel": ("free", 0.11, "ok"),
    "pandi_whois_intel": ("free", 0.10, "empty"),
    "data_go_id_intel": ("free", 0.13, "ok"),
    "social_dorks_intel": ("free", 0.12, "ok"),
    "google_dork_intel": ("free", 0.14, "ok"),
    "pddikti_intel": ("free", 0.10, "ok"),
    "tech_jobs_intel": ("free", 0.11, "empty"),
    "bts_intel": ("free", 0.09, "ok"),
    "whatsapp_check": ("free", 0.08, "ok"),
}

_ALL_SOURCES = sorted(_SIM_SOURCES)


async def _simulated_scan(source_name: str, target: str) -> dict:
    """Simulate run_source_scan / run_free_intel_scan for one source."""
    kind, latency, outcome = _SIM_SOURCES[source_name]
    await asyncio.sleep(latency)
    if outcome == "rate_limit":
        raise RuntimeError(f"{source_name}: 429 rate limited")
    if outcome == "error":
        raise ConnectionError(f"{source_name}: connection reset")
    if outcome == "empty":
        return {"source": source_name, "target": target, "findings": [], "status": "empty"}
    return {
        "source": source_name,
        "target": target,
        "findings": [{"id": f"f-{source_name}", "title": f"{source_name} hit"}],
        "status": "ok",
    }


# ── Naive batch: run every adapter, tolerate failures ─────────────────────────


async def naive_batch(target: str) -> dict:
    """Baseline: fire all sources, collect whatever succeeds."""
    started = time.monotonic()
    attempted = 0
    ok = 0
    errors = 0
    findings = 0
    for src in _ALL_SOURCES:
        attempted += 1
        try:
            res = await _simulated_scan(src, target)
            ok += 1
            findings += len(res["findings"])
        except Exception:
            errors += 1
    return {
        "attempted": attempted,
        "ok": ok,
        "errors": errors,
        "findings": findings,
        "elapsed_s": round(time.monotonic() - started, 3),
    }


# ── Agent loop: planner picks relevant sources, falls back on failure ─────────

_planner = AgentScanPlanner()


async def agent_loop_scan(target: str, max_sources: int = 12) -> dict:
    """Agent loop with the same simulated backends."""
    # Patch the module-level scan functions to route into our simulator.
    import src.modules.deep_scan.agent_loop as al

    async def _fake_source(
        name: str,
        target: str,
        source_inst=None,
        requester: str = "bench",
        requester_tier=None,
    ) -> object:
        from src.core.models import ScanResult

        res = await _simulated_scan(name, target)
        if res["status"] == "empty":
            return None
        return ScanResult(
            scan_id=f"{name}-bench",
            module=name,
            target=target,
            status="ok",
            findings=[],
        )

    async def _fake_free(
        name: str,
        target: str,
        requester: str = "bench",
        requester_tier=None,
    ) -> object:
        from src.core.models import ScanResult

        res = await _simulated_scan(name, target)
        if res["status"] == "empty":
            return None
        return ScanResult(
            scan_id=f"{name}-bench",
            module=name,
            target=target,
            status="ok",
            findings=[],
        )

    al.run_source_scan = _fake_source  # type: ignore[assignment]
    al.run_free_intel_scan = _fake_free  # type: ignore[assignment]

    started = time.monotonic()
    report = await run_agent_scan(target, max_sources=max_sources, requester="bench")
    elapsed = time.monotonic() - started

    return {
        "attempted": sum(1 for s in report.steps if s.attempted),
        "ok": sum(1 for s in report.steps if s.ok),
        "failed": sum(1 for s in report.steps if s.attempted and not s.ok),
        "deferred": sum(1 for s in report.steps if not s.attempted),
        "elapsed_s": round(elapsed, 3),
    }


async def main() -> None:
    print("=" * 68)
    print("  Head-to-head: S4 agent loop vs naive batch scan")
    print("=" * 68)
    print("  Scenario: email target — 2 breach sources rate-limit, 1 errors,")
    print("  free intel alternates available. 19 simulated sources total.")
    print("=" * 68)

    naive = await naive_batch("victim@example.com")
    agent = await agent_loop_scan("victim@example.com")

    print(
        f"\n  Naive batch        : attempted={naive['attempted']:2d} "
        f"ok={naive['ok']:2d} errors={naive['errors']:2d} "
        f"elapsed={naive['elapsed_s']:>6.2f}s"
    )
    print(
        f"  Agent loop (S4)    : attempted={agent['attempted']:2d} "
        f"ok={agent['ok']:2d} failed={agent['failed']:2d} "
        f"deferred={agent['deferred']:2d} elapsed={agent['elapsed_s']:>6.2f}s"
    )

    # Normalize: agent only runs what the planner picked (bounded by max_sources)
    print(f"\n  Wall-clock speedup : {naive['elapsed_s'] / max(agent['elapsed_s'], 1e-9):.2f}x")
    print(
        f"  Sources touched    : {agent['attempted']} vs {naive['attempted']} "
        f"({naive['attempted'] - agent['attempted']} unnecessary calls avoided)"
    )
    print(
        f"  Failed sources     : {agent['failed']} (agent pivoted to alternates; "
        f"naive accumulated {naive['errors']} raw errors)"
    )
    print("  Note: 'deferred' steps are alternates the planner never needed to")
    print("  run because enough primary/alternate sources already succeeded.")
    print("=" * 68)


if __name__ == "__main__":
    asyncio.run(main())
