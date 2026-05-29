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
"""

import argparse
import asyncio
import sys
import time
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def run_benchmark(workers: int = 20, duration: int = 60) -> None:
    """Run the scanner for a fixed duration and report metrics."""
    from src.modules.crypto.balance.scanner_engine import RandomScanner
    from src.modules.crypto.balance.chains import ALL_CHAINS

    print(f"=" * 60)
    print(f"  Scanner Throughput Benchmark")
    print(f"=" * 60)
    print(f"  Workers:   {workers}")
    print(f"  Duration:  {duration}s")
    print(f"  Chains:    {', '.join(c.symbol for c in ALL_CHAINS)}")
    print(f"=" * 60)

    scanner = RandomScanner(
        workers=workers,
        chains=list(ALL_CHAINS),
    )

    start = time.monotonic()
    stats = await scanner.run(duration_sec=duration)
    elapsed = time.monotonic() - start

    error_rate = (
        (stats.api_errors / stats.addresses_checked * 100)
        if stats.addresses_checked > 0
        else 0.0
    )

    print(f"")
    print(f"=" * 60)
    print(f"  BENCHMARK RESULTS")
    print(f"=" * 60)
    print(f"  Elapsed:           {elapsed:.1f}s")
    print(f"  Mnemonics:         {stats.mnemonics_generated}")
    print(f"  Addresses:         {stats.addresses_checked}")
    print(f"  Hits:              {stats.hits_found}")
    print(f"  API Errors:        {stats.api_errors}")
    print(f"  Mnemonics/sec:     {stats.mnemonics_per_sec:.1f}")
    print(f"  Addresses/sec:     {stats.addresses_checked / elapsed:.1f}")
    print(f"  Error Rate:        {error_rate:.1f}%")
    print(f"=" * 60)

    # Verdict
    target_mnemonics_per_sec = 20.0
    target_error_rate = 10.0

    passes = True
    if stats.mnemonics_per_sec < target_mnemonics_per_sec:
        print(f"  FAIL: Mnemonics/sec ({stats.mnemonics_per_sec:.1f}) < target ({target_mnemonics_per_sec})")
        passes = False
    else:
        print(f"  PASS: Mnemonics/sec ({stats.mnemonics_per_sec:.1f}) >= target ({target_mnemonics_per_sec})")

    if error_rate > target_error_rate:
        print(f"  FAIL: Error rate ({error_rate:.1f}%) > target ({target_error_rate}%)")
        passes = False
    else:
        print(f"  PASS: Error rate ({error_rate:.1f}%) <= target ({target_error_rate}%)")

    print(f"=" * 60)

    if passes:
        print(f"  OVERALL: PASS")
    else:
        print(f"  OVERALL: FAIL")
    print(f"=" * 60)

    sys.exit(0 if passes else 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner Throughput Benchmark")
    parser.add_argument("--workers", type=int, default=20, help="Number of async workers")
    parser.add_argument("--duration", type=int, default=60, help="Benchmark duration in seconds")
    args = parser.parse_args()

    asyncio.run(run_benchmark(workers=args.workers, duration=args.duration))


if __name__ == "__main__":
    main()
