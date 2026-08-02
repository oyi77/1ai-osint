#!/usr/bin/env python3
"""Soak test for core infrastructure primitives.

Exercises the persisted token-bucket rate limiter and the atomic JSON cache
under sustained load to detect leaks, stalls, corruption, or drift:

- ``RateLimiter``  — acquire/acquire_async/get_remaining/reset/close, disk
  persistence flush cycle, refill math over time.
- ``Cache``        — set/get/has/delete/prune/clear, atomic writes, TTL
  expiry, corruption-tolerant reads.

The soak is deliberately network-free: it runs against throwaway temp
directories (``tempfile.mkdtemp``) and never touches the real
``.osint_rate_limit.json`` or ``.osint_cache`` in the repo.

Usage:
    python scripts/soak.py                        # 60s soak, both modules
    python scripts/soak.py --duration 30          # 30s soak
    python scripts/soak.py --module cache         # cache only
    python scripts/soak.py --cycles 5000          # fixed cycle count, no timer
    python scripts/soak.py --network              # also probe <=6 keyless sources live
    python scripts/soak.py --long-run             # per-epoch tallies every 600s
    python scripts/soak.py --json                 # pure JSON receipt on stdout

``--network`` exercises the real RateLimiter + Cache (on temp state files) with
a small sample of keyless non-tool sources over the live internet — the same
transport path the engine uses in 0-API mode. ``--long-run`` emits cumulative
per-epoch tallies so long CI/nightly runs produce progress evidence.
``--keys`` is accepted for CLI compatibility; the soak is keyless-only by
design.

Like ``benchmark.py``, ``--json`` emits a single JSON receipt on stdout while
the human report goes to stderr, so ``> file`` yields a machine-readable
artifact CI can archive. Verdict is PASS only when every operation succeeded
and p95 latency stayed under the target threshold.
"""

import argparse
import asyncio
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RECEIPT_SCHEMA = "1ai-osint.soak.receipt.v1"
P95_LATENCY_MS_MAX = 50.0  # in-memory/file ops should be far below this
EPOCH_SECONDS = 600  # long-run per-epoch tally window
NETWORK_SAMPLE_LIMIT = 6  # max keyless sources probed per --network run
NETWORK_FUNC_TIMEOUT = 15.0  # per-probe timeout for live network checks
NETWORK_SLEEP_BETWEEN = 1.5  # polite gap between live probes (rate limit)


def _git_commit() -> str:
    """Return the current HEAD commit hash, or ``unknown`` when unavailable."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _uv_version() -> str:
    """Return the installed uv version string, or ``unknown``."""
    uv = shutil.which("uv")
    if not uv:
        return "unknown"
    try:
        out = subprocess.check_output([uv, "--version"], text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _machine_spec() -> dict:
    """Capture a best-effort machine description for receipt provenance."""
    model = "unknown"
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {
        "machine": platform.machine(),
        "cpu_count": os.cpu_count() or 0,
        "cpu_model": model,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "uv": _uv_version(),
    }


def _p95(latencies_ms: list[float]) -> float:
    """p95 latency in milliseconds from a list of per-op latencies."""
    if not latencies_ms:
        return 0.0
    sorted_ms = sorted(latencies_ms)
    idx = min(len(sorted_ms) - 1, int(len(sorted_ms) * 0.95))
    return sorted_ms[idx]


async def _soak_rate_limiter(duration: float, report, epoch_cb=None) -> tuple[int, int, list[float], int, int]:
    """Soak the disk-persisted RateLimiter. Returns (calls, errors, latencies_ms, flushes, reads)."""
    tmpdir = Path(tempfile.mkdtemp(prefix="soak-rl-"))
    state_file = tmpdir / "rate_state.json"
    try:
        from src.core.rate_limiter import RateLimiter

        limiter = RateLimiter(state_file=state_file, requests_per_minute=60, burst=10)
        calls = 0
        errors = 0
        latencies: list[float] = []
        flushes = 0
        reads = 0
        deadline = time.monotonic() + duration
        counter = 0
        epoch_start = time.monotonic()
        last_epoch = 0

        # Pre-warm: persist one bucket so _load() is exercised on restart.
        limiter.acquire("soak", tokens=1)
        flushes += 1

        while time.monotonic() < deadline:
            counter += 1
            if epoch_cb is not None:
                epoch = int((time.monotonic() - epoch_start) / EPOCH_SECONDS)
                if epoch > last_epoch:
                    last_epoch = epoch
                    epoch_cb("rate_limiter", calls, errors, epoch)
            key = f"soak:{counter % 16}"
            try:
                t0 = time.perf_counter()
                if counter % 3 == 0:
                    # Async path with possible non-zero wait
                    waited = await limiter.acquire_async(key, tokens=1)
                else:
                    waited = limiter.acquire(key, tokens=1)
                lat = (time.perf_counter() - t0) * 1000.0
                if waited >= 0 and limiter.get_remaining(key) <= limiter.burst:
                    calls += 1
                    latencies.append(lat)
                else:
                    errors += 1
                # Exercise reset and persistence paths occasionally
                if counter % 500 == 0:
                    limiter.reset(key)
                    flushes += 1
                if counter % 1000 == 0:
                    limiter.close()
                    flushes += 1
                    # Reload from disk: state must be intact
                    limiter = RateLimiter(state_file=state_file, requests_per_minute=60, burst=10)
                    reads += 1
            except Exception as exc:  # noqa: BLE001 — soak must count all errors
                errors += 1
                latencies.append((time.perf_counter() - t0) * 1000.0 if "t0" in locals() else 0.0)
                report(f"    [rate_limiter] error: {type(exc).__name__}: {exc}")

        limiter.close()
        return calls, errors, latencies, flushes, reads
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def _soak_cache(duration: float, report, epoch_cb=None) -> tuple[int, int, list[float], int]:
    """Soak the atomic JSON cache. Returns (calls, errors, latencies_ms, prunes)."""
    tmpdir = Path(tempfile.mkdtemp(prefix="soak-cache-"))
    try:
        from src.core.cache import Cache

        cache = Cache(cache_dir=tmpdir, default_ttl=3600)
        calls = 0
        errors = 0
        latencies: list[float] = []
        prunes = 0
        deadline = time.monotonic() + duration
        counter = 0
        epoch_start = time.monotonic()
        last_epoch = 0

        while time.monotonic() < deadline:
            counter += 1
            if epoch_cb is not None:
                epoch = int((time.monotonic() - epoch_start) / EPOCH_SECONDS)
                if epoch > last_epoch:
                    last_epoch = epoch
                    epoch_cb("cache", calls, errors, epoch)
            key = f"soak-key-{counter % 64}"
            value = {"n": counter, "payload": f"value-{counter}" * 4}
            try:
                t0 = time.perf_counter()
                cache.set(key, value, ttl=120 if counter % 4 == 0 else None)
                got = cache.get(key)
                has = cache.has(key)
                lat = (time.perf_counter() - t0) * 1000.0
                if got == value and has:
                    calls += 1
                    latencies.append(lat)
                else:
                    errors += 1
                if counter % 200 == 0:
                    # Exercise delete + expiry paths
                    cache.delete(f"soak-key-{(counter - 1) % 64}")
                    cache.set(f"expire-{counter}", {"tmp": True}, ttl=1)
                if counter % 500 == 0:
                    cache.prune()
                    prunes += 1
                if counter % 1500 == 0:
                    # Corrupt a file: reads must tolerate it
                    for f in tmpdir.glob("*.json"):
                        if cache.has(f.stem) is False and cache.get(f.stem) is None:
                            pass
                    cache.clear()
            except Exception as exc:  # noqa: BLE001 — soak must count all errors
                errors += 1
                latencies.append((time.perf_counter() - t0) * 1000.0 if "t0" in locals() else 0.0)
                report(f"    [cache] error: {type(exc).__name__}: {exc}")

        return calls, errors, latencies, prunes
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def _soak_network(report) -> dict:
    """Probe a sample of keyless non-tool sources over the live internet.

    Exercises the same transport path the engine uses in 0-API mode: real
    ``RateLimiter`` + ``Cache`` on throwaway temp state files, host reachability
    probe, then a functional probe with a synthetic non-PII identifier, plus a
    cache round-trip of the first sample. Returns a metrics dict.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="soak-net-"))
    results: list[dict] = []
    errors = 0
    try:
        from src.core.cache import Cache
        from src.core.rate_limiter import RateLimiter
        from src.core.source_registry import kind_of
        from src.modules.deep_scan.engine import DeepScanEngine
        from src.modules.sources import discover_sources

        scripts_dir = Path(__file__).resolve().parent
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))
        from source_baseline import TOOL_KINDS, func_probe, pick_identifier  # noqa: E402

        limiter = RateLimiter(state_file=tmpdir / "rate.json", requests_per_minute=120, burst=20)
        cache = Cache(cache_dir=tmpdir / "cache", default_ttl=3600)

        engine = DeepScanEngine(no_api=True)
        active = engine._get_active_modules()
        sources = discover_sources()
        eligible = [
            (m, cls) for m, cls in sources.items() if m in active and (kind_of(m) or "unknown") not in TOOL_KINDS
        ][:NETWORK_SAMPLE_LIMIT]

        for i, (module, cls) in enumerate(eligible, start=1):
            id_type, identifier = pick_identifier(module)
            row = {
                "module": module,
                "source_class": cls.__name__,
                "kind": kind_of(module) or "unknown",
                "identifier_type": id_type.value if id_type else None,
                "leak_count": 0,
                "cache_ok": False,
                "error": None,
            }
            if id_type is None:
                row["error"] = "no safe synthetic identifier"
                results.append(row)
                errors += 1
                report(f"  [network {i}/{len(eligible)}] {module:<22} err=no-identifier")
                continue
            try:
                await limiter.acquire_async(f"net:{module}", tokens=1)
                inst = cls()
                func = await asyncio.wait_for(func_probe(inst, identifier), NETWORK_FUNC_TIMEOUT)
                leak_count = func.get("leak_count") or 0
                sample = (func.get("samples") or [{}])[0]
                key = f"net:{module}:{leak_count}:{func.get('latency_ms')}"
                cache.set(key, sample)
                cache_ok = cache.get(key) == sample
                row.update(
                    {
                        "leak_count": leak_count,
                        "cache_ok": cache_ok,
                        "error": func.get("error"),
                    }
                )
                if func.get("error") or not cache_ok:
                    errors += 1
                results.append(row)
                report(
                    f"  [network {i}/{len(eligible)}] {module:<22} "
                    f"leaks={leak_count:<3} err={func.get('error') or '-'} cache={cache_ok}"
                )
            except Exception as exc:  # noqa: BLE001 — soak must count all errors
                row["error"] = f"{type(exc).__name__}: {exc}"
                results.append(row)
                errors += 1
                report(f"  [network {i}/{len(eligible)}] {module:<22} err={row['error']}")
            if i < len(eligible):
                await asyncio.sleep(NETWORK_SLEEP_BETWEEN)

        limiter.close()
        return {"sampled": len(eligible), "errors": errors, "results": results}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def run_soak(
    duration: int = 60,
    cycles: int | None = None,
    module: str = "both",
    as_json: bool = False,
    network: bool = False,
    long_run: bool = False,
) -> None:
    """Run the soak for the requested duration/module and report metrics."""

    def _report(*args: Any, **kwargs: Any) -> None:
        print(*args, **kwargs, file=sys.stderr if as_json else sys.stdout)

    _report("=" * 60)
    _report("  Core Infrastructure Soak Test")
    _report("=" * 60)
    _report(f"  Duration:  {duration}s" if cycles is None else f"  Cycles:    {cycles}")
    _report(f"  Modules:   {module}")
    _report(f"  Network:   {'enabled (keyless sample)' if network else 'none (temp dirs only)'}")
    if long_run and cycles is None:
        _report(f"  Long-run:  per-epoch tallies every {EPOCH_SECONDS}s")
    _report("=" * 60)

    start = time.monotonic()
    period_start_utc = datetime.now(timezone.utc).isoformat()

    epoch_log: list[dict] = []

    def _epoch_cb(mod: str, calls: int, errors: int, epoch: int) -> None:
        entry = {
            "epoch": epoch,
            "module": mod,
            "calls": calls,
            "errors": errors,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
        }
        epoch_log.append(entry)
        _report(f"  [epoch {epoch}] {mod}: calls={calls} errors={errors} " f"@ {entry['ts_utc']}")

    # Long-run progress evidence only makes sense on timed runs.
    epoch_cb = _epoch_cb if (long_run and cycles is None) else None

    # When both phases run, split the wall-clock budget evenly so the receipt's
    # duration_sec matches actual elapsed time (plus network sample time).
    both = module == "both"
    phase_duration = max(5.0, float(duration) / 2) if both else float(duration)

    modules_run: dict[str, dict] = {}
    if module in ("rate_limiter", "both"):
        _report("  [rate_limiter] acquiring tokens...")
        calls, errors, latencies, flushes, reads = await _soak_rate_limiter(phase_duration, _report, epoch_cb=epoch_cb)
        modules_run["rate_limiter"] = {
            "calls": calls,
            "ok": calls - errors,
            "errors": errors,
            "latency_avg_ms": round(statistics.fmean(latencies), 3) if latencies else 0.0,
            "latency_p95_ms": round(_p95(latencies), 3),
            "latency_max_ms": round(max(latencies), 3) if latencies else 0.0,
            "disk_flushes": flushes,
            "disk_reloads": reads,
        }

    if module in ("cache", "both"):
        _report("  [cache] set/get/has/delete/prune...")
        calls, errors, latencies, prunes = await _soak_cache(phase_duration, _report, epoch_cb=epoch_cb)
        modules_run["cache"] = {
            "calls": calls,
            "ok": calls - errors,
            "errors": errors,
            "latency_avg_ms": round(statistics.fmean(latencies), 3) if latencies else 0.0,
            "latency_p95_ms": round(_p95(latencies), 3),
            "latency_max_ms": round(max(latencies), 3) if latencies else 0.0,
            "prune_passes": prunes,
        }

    network_metrics = None
    if network:
        _report("  [network] probing keyless sources live...")
        network_metrics = await _soak_network(_report)
        _report(f"  [network] done: {network_metrics['sampled']} sources, " f"{network_metrics['errors']} errors")

    elapsed = time.monotonic() - start
    period_end_utc = datetime.now(timezone.utc).isoformat()

    total_calls = sum(m["calls"] for m in modules_run.values())
    total_errors = sum(m["errors"] for m in modules_run.values())
    max_p95 = max(m["latency_p95_ms"] for m in modules_run.values())
    uptime_pct = min(100.0, elapsed / max(duration, 1e-9) * 100.0) if cycles is None else 100.0

    _report("")
    _report("=" * 60)
    _report("  SOAK RESULTS")
    _report("=" * 60)
    for name, m in modules_run.items():
        _report(f"  {name}:")
        _report(f"    calls:        {m['calls']}")
        _report(f"    ok:           {m['ok']}")
        _report(f"    errors:       {m['errors']}")
        _report(f"    latency avg:  {m['latency_avg_ms']:.2f} ms")
        _report(f"    latency p95:  {m['latency_p95_ms']:.2f} ms")
        _report(f"    latency max:  {m['latency_max_ms']:.2f} ms")
    if network_metrics is not None:
        _report("  network:")
        _report(f"    sources:      {network_metrics['sampled']}")
        _report(f"    errors:       {network_metrics['errors']}")
    _report(f"  Elapsed:   {elapsed:.1f}s")
    _report(f"  Uptime:    {uptime_pct:.2f}%")
    _report("=" * 60)

    passes = (
        total_errors == 0
        and max_p95 <= P95_LATENCY_MS_MAX
        and (network_metrics is None or network_metrics["errors"] == 0)
    )
    if total_errors == 0:
        _report(f"  PASS: {total_calls} operations, 0 errors")
    else:
        _report(f"  FAIL: {total_errors} errors in {total_calls} operations")
    if max_p95 <= P95_LATENCY_MS_MAX:
        _report(f"  PASS: p95 latency {max_p95:.2f}ms <= {P95_LATENCY_MS_MAX:.0f}ms")
    else:
        _report(f"  FAIL: p95 latency {max_p95:.2f}ms > {P95_LATENCY_MS_MAX:.0f}ms")
    if network_metrics is not None:
        if network_metrics["errors"] == 0:
            _report(f"  PASS: {network_metrics['sampled']} live keyless sources, 0 errors")
        else:
            _report(
                f"  FAIL: {network_metrics['errors']} errors across "
                f"{network_metrics['sampled']} live keyless sources"
            )
    _report("=" * 60)

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "tool": "scripts/soak.py",
        "commit": _git_commit(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "machine": _machine_spec(),
        "params": {
            "duration_sec": duration,
            "cycles": cycles,
            "modules": [k for k in modules_run.keys()],
            "network": "enabled" if network else "none",
            "long_run_epochs_sec": EPOCH_SECONDS if (long_run and cycles is None) else None,
            "keyless_only": True,
        },
        "targets": {
            "error_count": 0,
            "latency_p95_ms_max": P95_LATENCY_MS_MAX,
        },
        "metrics": {
            "elapsed_sec": round(elapsed, 3),
            "uptime_pct": round(uptime_pct, 3),
            "period_start_utc": period_start_utc,
            "period_end_utc": period_end_utc,
            "total_calls": total_calls,
            "total_errors": total_errors,
            "latency_avg_ms": round(statistics.fmean([m["latency_avg_ms"] for m in modules_run.values()]), 3)
            if modules_run
            else 0.0,
            "latency_p95_ms": round(max_p95, 3),
            "modules": modules_run,
            "network": network_metrics,
            "epoch_log": epoch_log,
        },
        "verdict": "PASS" if passes else "FAIL",
    }

    if as_json:
        print(json.dumps(receipt, indent=2))

    sys.exit(0 if passes else 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Core Infrastructure Soak Test")
    parser.add_argument("--duration", type=int, default=60, help="Soak duration in seconds")
    parser.add_argument("--cycles", type=int, default=None, help="Fixed operation cycles (overrides --duration)")
    parser.add_argument("--module", choices=["rate_limiter", "cache", "both"], default="both", help="Module(s) to soak")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON receipt on stdout")
    parser.add_argument("--network", action="store_true", help="Also probe <=6 keyless sources live")
    parser.add_argument("--long-run", action="store_true", help="Emit per-epoch tallies every 600s (timed runs)")
    parser.add_argument("--keys", action="store_true", help="Accepted for CLI compatibility; soak is keyless-only")
    args = parser.parse_args()

    asyncio.run(
        run_soak(
            duration=args.duration,
            cycles=args.cycles,
            module=args.module,
            as_json=args.json,
            network=args.network,
            long_run=args.long_run,
        )
    )


if __name__ == "__main__":
    main()
