"""Benchmark for mnemonic derivation throughput and API latency.

Part 1: Measures single-threaded mnemonics/sec for derive_from_mnemonic()
with ETH, BSC, Polygon, BTC, and SOL over 100 iterations.
Gate thresholds for concurrency strategy:
  >= 1000 mnemonics/sec  -> pure async OK
  500-1000               -> need run_in_executor
  < 500                  -> need multiprocessing

Part 2: Benchmarks free API throughput (blockstream.info, eth.llamarpc.com).

Usage:
    pytest tests/benchmarks/benchmark_derivation.py -v -s
"""

from __future__ import annotations

import asyncio
import statistics
import time

import httpx

from src.modules.crypto.balance.chains import ALL_CHAINS, ETHEREUM, BITCOIN
from src.modules.crypto.balance.deriver import derive_from_mnemonic

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)
ITERATIONS = 100


def test_derivation_throughput() -> None:
    """Benchmark derive_from_mnemonic() over 100 iterations with all 5 chains."""
    # Warm-up: seed the crypto libs
    derive_from_mnemonic(TEST_MNEMONIC, chains=ALL_CHAINS)

    start = time.perf_counter()
    for _ in range(ITERATIONS):
        results = derive_from_mnemonic(TEST_MNEMONIC, chains=ALL_CHAINS)
    elapsed = time.perf_counter() - start

    mnemonics_per_sec = ITERATIONS / elapsed
    addresses_per_call = len(results)

    # Determine concurrency strategy
    if mnemonics_per_sec >= 1000:
        strategy = "pure async OK"
    elif mnemonics_per_sec >= 500:
        strategy = "need run_in_executor"
    else:
        strategy = "need multiprocessing"

    print(f"\n{'=' * 60}")
    print("  Derivation Throughput Benchmark")
    print(f"{'=' * 60}")
    print(f"  Chains:        {', '.join(c.symbol for c in ALL_CHAINS)}")
    print(f"  Iterations:    {ITERATIONS}")
    print(f"  Addresses/run: {addresses_per_call}")
    print(f"  Total time:    {elapsed:.3f}s")
    print(f"  Throughput:    {mnemonics_per_sec:.1f} mnemonics/sec")
    print(f"  Per derivation:{elapsed / ITERATIONS * 1000:.1f} ms")
    print(f"  Strategy:      {strategy}")
    print(f"{'=' * 60}")

    # Gate: must exceed 100 mnemonics/sec (minimum viable)
    assert mnemonics_per_sec >= 100, (
        f"Throughput {mnemonics_per_sec:.1f} mnemonics/sec is below the 100/sec gate. "
        f"Investigate optimization."
    )


# --- API Throughput Benchmarks ---

async def _benchmark_btc_api(n_requests: int = 10) -> dict:
    """Benchmark blockstream.info API latency."""
    url = f"{BITCOIN.api_url}/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    latencies: list[float] = []
    errors = 0

    async with httpx.AsyncClient(timeout=15) as client:
        for _ in range(n_requests):
            start = time.perf_counter()
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                latencies.append(time.perf_counter() - start)
            except Exception:
                errors += 1
                latencies.append(time.perf_counter() - start)

    return {
        "endpoint": "blockstream.info",
        "requests": n_requests,
        "errors": errors,
        "avg_ms": statistics.mean(latencies) * 1000 if latencies else 0,
        "median_ms": statistics.median(latencies) * 1000 if latencies else 0,
        "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] * 1000 if latencies else 0,
    }


async def _benchmark_eth_api(n_requests: int = 10) -> dict:
    """Benchmark eth.llamarpc.com JSON-RPC latency."""
    url = ETHEREUM.rpc_url
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "latest"],
        "id": 1,
    }
    latencies: list[float] = []
    errors = 0

    async with httpx.AsyncClient(timeout=15) as client:
        for _ in range(n_requests):
            start = time.perf_counter()
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                latencies.append(time.perf_counter() - start)
            except Exception:
                errors += 1
                latencies.append(time.perf_counter() - start)

    return {
        "endpoint": "eth.llamarpc.com",
        "requests": n_requests,
        "errors": errors,
        "avg_ms": statistics.mean(latencies) * 1000 if latencies else 0,
        "median_ms": statistics.median(latencies) * 1000 if latencies else 0,
        "p95_ms": sorted(latencies)[int(len(latencies) * 0.95)] * 1000 if latencies else 0,
    }


def test_api_throughput() -> None:
    """Benchmark free API endpoints: blockstream.info and eth.llamarpc.com."""
    btc_stats = asyncio.run(_benchmark_btc_api())
    eth_stats = asyncio.run(_benchmark_eth_api())

    print(f"\n{'=' * 60}")
    print("  API Throughput Benchmark")
    print(f"{'=' * 60}")
    for stats in [btc_stats, eth_stats]:
        print(f"\n  Endpoint:   {stats['endpoint']}")
        print(f"  Requests:   {stats['requests']}")
        print(f"  Errors:     {stats['errors']}")
        print(f"  Avg:        {stats['avg_ms']:.1f} ms")
        print(f"  Median:     {stats['median_ms']:.1f} ms")
        print(f"  P95:        {stats['p95_ms']:.1f} ms")
    print(f"\n{'=' * 60}")

    # Report-only: API availability is outside our control.
    # Log warnings for high error rates but do not fail the benchmark.
    for stats in [btc_stats, eth_stats]:
        error_rate = stats["errors"] / stats["requests"] if stats["requests"] else 0
        if error_rate > 0.5:
            print(f"  WARNING: {stats['endpoint']} error rate {error_rate:.0%} "
                  f"({stats['errors']}/{stats['requests']})")
        else:
            print(f"  OK: {stats['endpoint']} error rate {error_rate:.0%}")
