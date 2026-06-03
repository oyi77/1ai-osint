"""Performance benchmarks for 1ai-osint modules.

Measures scan speed, graph construction time, memory usage, and throughput
for the ZKIT pipeline and individual modules.

Usage:
    pytest tests/benchmarks/benchmark_performance.py -v --tb=short
    pytest tests/benchmarks/benchmark_performance.py -k "test_graph" --benchmark-json=perf.json
"""

from __future__ import annotations

import secrets
import sys
import time

import pytest

from src.modules.identity_tracking.identity_graph import IdentityGraph, NodeType
from src.modules.identity_tracking.zkit_engine import ZKITEngine


# ---------------------------------------------------------------------------
# Test data generators
# ---------------------------------------------------------------------------


def _generate_records(n: int) -> list[dict]:
    """Generate n synthetic identity records with realistic distributions."""
    records = []
    domains = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com", "test.org"]
    for i in range(n):
        domain = domains[i % len(domains)]
        records.append(
            {
                "email": f"user{i}@{domain}",
                "username": f"user_{i}",
                "phone": f"+1555{i:07d}",
                "domain": domain,
                "source": f"source_{i % 5}",
            }
        )
    return records


def _generate_overlapping_records(n_groups: int, records_per_group: int) -> list[dict]:
    """Generate records with shared attributes to create graph edges.

    Each group shares one common email, producing connected components.
    """
    records = []
    for g in range(n_groups):
        shared_email = f"group{g}@shared.com"
        for i in range(records_per_group):
            records.append(
                {
                    "email": shared_email,
                    "username": f"group{g}_user{i}",
                    "phone": f"+1555{g:03d}{i:04d}",
                }
            )
    return records


# ---------------------------------------------------------------------------
# Benchmark: Hash throughput
# ---------------------------------------------------------------------------


class TestHashPerformance:
    """Benchmark ZKIT hashing throughput."""

    def test_single_hash_latency(self) -> None:
        """Measure latency of a single SHA-256 hash operation."""
        salt = secrets.token_hex(32)
        graph = IdentityGraph(salt=salt)
        iterations = 10_000

        start = time.perf_counter()
        for i in range(iterations):
            graph.hash_attribute(f"test_user_{i}@example.com")
        elapsed = time.perf_counter() - start

        per_hash_ns = (elapsed / iterations) * 1e9
        print("\n=== Hash Throughput ===")
        print(f"  Iterations:   {iterations}")
        print(f"  Total time:   {elapsed:.4f}s")
        print(f"  Per hash:     {per_hash_ns:.0f}ns")
        print(f"  Throughput:   {iterations / elapsed:,.0f} hashes/sec")

        # SHA-256 should be well under 10 microseconds per hash
        assert per_hash_ns < 100_000, f"Hash latency {per_hash_ns:.0f}ns exceeds 100us"

    def test_batch_hash_throughput(self) -> None:
        """Measure throughput for hashing batches of records."""
        salt = ZKITEngine.new_salt()
        engine = ZKITEngine(salt=salt, investigation_id="perf-test")

        for n in [100, 1_000, 10_000]:
            records = _generate_records(n)

            start = time.perf_counter()
            ingested = engine.ingest(records)
            hashed = engine.hash_records(ingested)  # noqa: F841
            elapsed = time.perf_counter() - start

            throughput = n / elapsed
            print(f"\n  n={n:>6}: {elapsed:.4f}s ({throughput:,.0f} records/sec)")

            # Should process at least 1000 records/sec
            assert throughput > 1000, f"Throughput {throughput:.0f} rec/sec below 1000"


# ---------------------------------------------------------------------------
# Benchmark: Graph construction
# ---------------------------------------------------------------------------


class TestGraphPerformance:
    """Benchmark identity graph construction time."""

    def test_graph_construction_scaling(self) -> None:
        """Measure graph construction time for varying record counts."""
        salt = ZKITEngine.new_salt()

        results = []
        for n in [100, 500, 1_000, 5_000]:
            engine = ZKITEngine(salt=salt, investigation_id=f"graph-perf-{n}")
            records = _generate_records(n)

            start = time.perf_counter()
            ingested = engine.ingest(records)
            hashed = engine.hash_records(ingested)
            engine.build_graph(hashed)
            elapsed = time.perf_counter() - start

            results.append(
                {
                    "n": n,
                    "time_s": elapsed,
                    "nodes": engine.graph.node_count,
                    "edges": engine.graph.edge_count,
                }
            )

        print("\n=== Graph Construction Performance ===")
        print(
            f"  {'Records':>8} | {'Time (s)':>10} | {'Nodes':>8} | {'Edges':>8} | {'ms/rec':>8}"
        )
        print(f"  {'-' * 8}-+-{'-' * 10}-+-{'-' * 8}-+-{'-' * 8}-+-{'-' * 8}")
        for r in results:
            ms_per = (r["time_s"] / r["n"]) * 1000
            print(
                f"  {r['n']:>8} | {r['time_s']:>10.4f} | {r['nodes']:>8} | "
                f"{r['edges']:>8} | {ms_per:>8.2f}"
            )

        # 5000 records should complete in under 10 seconds
        large = results[-1]
        assert large["time_s"] < 10.0, (
            f"Graph construction for {large['n']} records took {large['time_s']:.2f}s"
        )

    def test_correlation_scaling(self) -> None:
        """Measure correlation (connected components) time for varying graph sizes."""
        salt = ZKITEngine.new_salt()
        records = _generate_overlapping_records(
            50, 10
        )  # 50 groups, 10 each = 500 records

        engine = ZKITEngine(salt=salt, investigation_id="corr-perf")
        ingested = engine.ingest(records)
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)

        start = time.perf_counter()
        components = engine.correlate()
        elapsed = time.perf_counter() - start

        print("\n=== Correlation Performance ===")
        print(f"  Nodes:      {engine.graph.node_count}")
        print(f"  Edges:      {engine.graph.edge_count}")
        print(f"  Components: {len(components)}")
        print(f"  Time:       {elapsed:.4f}s")

        assert elapsed < 5.0, f"Correlation took {elapsed:.2f}s (limit: 5s)"

    def test_scoring_performance(self) -> None:
        """Measure cluster scoring time."""
        salt = ZKITEngine.new_salt()
        records = _generate_overlapping_records(20, 15)  # 300 records

        engine = ZKITEngine(salt=salt, investigation_id="score-perf")
        ingested = engine.ingest(records)
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)
        components = engine.correlate()

        start = time.perf_counter()
        clusters = engine.score_components(components)
        elapsed = time.perf_counter() - start

        print("\n=== Scoring Performance ===")
        print(f"  Components: {len(components)}")
        print(f"  Clusters:   {len(clusters)}")
        print(f"  Time:       {elapsed:.4f}s")

        assert elapsed < 5.0, f"Scoring took {elapsed:.2f}s (limit: 5s)"


# ---------------------------------------------------------------------------
# Benchmark: Memory usage
# ---------------------------------------------------------------------------


class TestMemoryUsage:
    """Benchmark memory consumption of graph structures."""

    def test_graph_memory_footprint(self) -> None:
        """Estimate memory usage of the identity graph."""
        try:
            import tracemalloc

            tracemalloc.start()
        except ImportError:
            pytest.skip("tracemalloc not available")

        salt = ZKITEngine.new_salt()
        engine = ZKITEngine(salt=salt, investigation_id="mem-test")
        records = _generate_records(5_000)

        snapshot_before = tracemalloc.take_snapshot()
        ingested = engine.ingest(records)
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)
        snapshot_after = tracemalloc.take_snapshot()

        tracemalloc.stop()

        # Compute memory delta
        stats_before = snapshot_before.statistics("lineno")
        stats_after = snapshot_after.statistics("lineno")

        total_before = sum(s.size for s in stats_before)
        total_after = sum(s.size for s in stats_after)
        delta_mb = (total_after - total_before) / (1024 * 1024)

        per_node_bytes = (
            (total_after - total_before) / engine.graph.node_count
            if engine.graph.node_count > 0
            else 0
        )

        print("\n=== Memory Usage (5000 records) ===")
        print(f"  Nodes:           {engine.graph.node_count}")
        print(f"  Edges:           {engine.graph.edge_count}")
        print(f"  Memory delta:    {delta_mb:.2f} MB")
        print(f"  Per node:        {per_node_bytes:.0f} bytes")

        # 5000 records should use less than 100 MB
        assert delta_mb < 100, f"Memory usage {delta_mb:.2f} MB exceeds 100 MB limit"

    def test_node_memory_estimate(self) -> None:
        """Estimate per-node memory from Pydantic model size."""
        graph = IdentityGraph(salt="test")

        # Add a node and measure its serialized size
        node_id = graph.hash_attribute("test@example.com")
        graph.add_node(node_id, NodeType.EMAIL_HASH, source="test")

        node = graph.get_node(node_id)
        serialized = node.model_dump_json()
        node_bytes = len(serialized.encode("utf-8"))

        print("\n=== Per-Node Memory Estimate ===")
        print(f"  Serialized node: {node_bytes} bytes")
        print(f"  For 100K nodes:  {node_bytes * 100_000 / (1024 * 1024):.1f} MB")

        assert node_bytes < 10_000, f"Node size {node_bytes} bytes exceeds 10KB"


# ---------------------------------------------------------------------------
# Benchmark: End-to-end pipeline
# ---------------------------------------------------------------------------


class TestEndToEndPerformance:
    """Benchmark full ZKIT pipeline throughput."""

    @pytest.mark.parametrize("n", [100, 500, 1_000])
    def test_full_pipeline_throughput(self, n: int) -> None:
        """Measure end-to-end pipeline time for n records."""
        salt = ZKITEngine.new_salt()
        engine = ZKITEngine(salt=salt, investigation_id=f"e2e-{n}")
        records = _generate_records(n)

        start = time.perf_counter()
        output = engine.run(records)
        elapsed = time.perf_counter() - start

        print(f"\n=== End-to-End Pipeline (n={n}) ===")
        print(f"  Time:       {elapsed:.4f}s")
        print(f"  Clusters:   {len(output.clusters)}")
        print(f"  Throughput: {n / elapsed:,.0f} records/sec")

        # Minimum throughput requirement
        assert elapsed < 30.0, f"Pipeline for {n} records took {elapsed:.2f}s"

    def test_graph_merge_performance(self) -> None:
        """Measure time to merge two graphs."""
        salt = ZKITEngine.new_salt()
        engine1 = ZKITEngine(salt=salt, investigation_id="merge-1")
        engine2 = ZKITEngine(salt=salt, investigation_id="merge-2")

        records1 = _generate_records(500)
        records2 = _generate_records(
            500,
        )  # may overlap

        # Build both graphs
        engine1.run(records1)
        engine2.run(records2)

        start = time.perf_counter()
        added = engine1.graph.merge_subgraphs(engine2.graph)
        elapsed = time.perf_counter() - start

        print("\n=== Graph Merge Performance ===")
        print(f"  Graph 1 nodes: {len(records1)}")
        print(f"  Graph 2 nodes: {len(records2)}")
        print(f"  New entities:  {added}")
        print(f"  Merged nodes:  {engine1.graph.node_count}")
        print(f"  Merge time:    {elapsed:.4f}s")

        assert elapsed < 5.0, f"Graph merge took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------


class TestBenchmarkSummary:
    """Aggregate benchmark summary for reporting."""

    def test_print_summary(self) -> None:
        """Print a summary table of all benchmark results."""
        print("\n" + "=" * 60)
        print("1ai-osint Performance Benchmark Summary")
        print("=" * 60)
        print(f"  Python:    {sys.version.split()[0]}")
        print(f"  Platform:  {sys.platform}")
        print("  Hash algo: SHA-256")
        print("  Graph:     In-memory Pydantic models")
        print("=" * 60)
