#!/usr/bin/env python3
"""Throughput benchmark for the crypto balance scanner.

Runs the scanner for a fixed duration and reports:
- Mnemonics/sec
- Addresses/sec
- API error rate
- Hit count

Usage:
    python scripts/benchmark.py                  # 60s benchmark
    python scripts/benchmark.py --duration 30    # 30s benchmark
    python scripts/benchmark.py --workers 50     # 50 workers
    python scripts/benchmark.py --json           # also emit machine-readable receipt

The ``--json`` mode emits a single JSON receipt on stdout while the human
report is written to stderr, so redirecting stdout to a file yields a pure
JSON artifact. The receipt carries the git commit, UTC timestamp, machine
spec, run params and metrics. That receipt is the reproducible artifact CI
archives; any two runs of the same commit on the same machine should produce
comparable receipts.
"""

import argparse
import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RECEIPT_SCHEMA = "1ai-osint.benchmark.receipt.v1"


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


async def run_benchmark(workers: int = 20, duration: int = 60, as_json: bool = False) -> None:
    """Run the scanner for a fixed duration and report metrics."""
    from src.modules.crypto.balance.chains import ALL_CHAINS
    from src.modules.crypto.balance.scanner_engine import RandomScanner

    # In --json mode the human report is routed to stderr so stdout carries
    # only the machine-readable receipt (pure JSON, safe for `> file` redirection).
    def _report(*args: object, **kwargs: object) -> None:
        print(*args, **kwargs, file=sys.stderr if as_json else sys.stdout)

    _report("=" * 60)
    _report("  Scanner Throughput Benchmark")
    _report("=" * 60)
    _report(f"  Workers:   {workers}")
    _report(f"  Duration:  {duration}s")
    _report(f"  Chains:    {', '.join(c.symbol for c in ALL_CHAINS)}")
    _report("=" * 60)

    scanner = RandomScanner(
        workers=workers,
        chains=list(ALL_CHAINS),
    )

    start = time.monotonic()
    stats = await scanner.run(duration_sec=duration)
    elapsed = time.monotonic() - start

    error_rate = (stats.api_errors / stats.addresses_checked * 100) if stats.addresses_checked > 0 else 0.0

    _report("")
    _report("=" * 60)
    _report("  BENCHMARK RESULTS")
    _report("=" * 60)
    _report(f"  Elapsed:           {elapsed:.1f}s")
    _report(f"  Mnemonics:         {stats.mnemonics_generated}")
    _report(f"  Addresses:         {stats.addresses_checked}")
    _report(f"  Hits:              {stats.hits_found}")
    _report(f"  API Errors:        {stats.api_errors}")
    _report(f"  Mnemonics/sec:     {stats.mnemonics_per_sec:.1f}")
    _report(f"  Addresses/sec:     {stats.addresses_checked / elapsed:.1f}")
    _report(f"  Error Rate:        {error_rate:.1f}%")
    _report("=" * 60)

    # Verdict
    target_mnemonics_per_sec = 20.0
    target_error_rate = 10.0

    passes = True
    if stats.mnemonics_per_sec < target_mnemonics_per_sec:
        _report(f"  FAIL: Mnemonics/sec ({stats.mnemonics_per_sec:.1f}) < target ({target_mnemonics_per_sec})")
        passes = False
    else:
        _report(f"  PASS: Mnemonics/sec ({stats.mnemonics_per_sec:.1f}) >= target ({target_mnemonics_per_sec})")

    if error_rate > target_error_rate:
        _report(f"  FAIL: Error rate ({error_rate:.1f}%) > target ({target_error_rate}%)")
        passes = False
    else:
        _report(f"  PASS: Error rate ({error_rate:.1f}%) <= target ({target_error_rate}%)")

    _report("=" * 60)

    if passes:
        _report("  OVERALL: PASS")
    else:
        _report("  OVERALL: FAIL")
    _report("=" * 60)

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "tool": "scripts/benchmark.py",
        "commit": _git_commit(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "machine": _machine_spec(),
        "params": {
            "workers": workers,
            "duration_sec": duration,
            "chains": [c.symbol for c in ALL_CHAINS],
        },
        "targets": {
            "mnemonics_per_sec": 20.0,
            "error_rate_pct_max": 10.0,
        },
        "metrics": {
            "elapsed_sec": round(elapsed, 3),
            "mnemonics_generated": stats.mnemonics_generated,
            "addresses_checked": stats.addresses_checked,
            "hits_found": stats.hits_found,
            "api_errors": stats.api_errors,
            "mnemonics_per_sec": round(stats.mnemonics_per_sec, 3),
            "addresses_per_sec": round(stats.addresses_checked / elapsed, 3),
            "error_rate_pct": round(error_rate, 3),
        },
        "verdict": "PASS" if passes else "FAIL",
    }

    if as_json:
        print(json.dumps(receipt, indent=2))

    sys.exit(0 if passes else 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner Throughput Benchmark")
    parser.add_argument("--workers", type=int, default=20, help="Number of async workers")
    parser.add_argument("--duration", type=int, default=60, help="Benchmark duration in seconds")
    parser.add_argument("--json", action="store_true", help="Also emit a machine-readable JSON receipt on stdout")
    args = parser.parse_args()

    asyncio.run(run_benchmark(workers=args.workers, duration=args.duration, as_json=args.json))


if __name__ == "__main__":
    main()
