<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 -->

# benchmarks

## Purpose
Performance benchmarks for key operations — derivation speed, detection accuracy, AI comparison.

## Key Files
| File | Description |
|------|-------------|
| `benchmark_derivation.py` | Address derivation performance |
| `benchmark_detection.py` | Detection accuracy benchmarks |
| `benchmark_ai_comparison.py` | AI model comparison benchmarks |
| `benchmark_performance.py` | General performance benchmarks |

## For AI Agents

### Working In This Directory
- Benchmarks are not part of the standard test suite (`testpaths = ["tests"]` in pyproject runs them anyway if executed from the root — use explicit paths)
- Run manually: `uv run pytest tests/benchmarks/` (all four files are pytest-style; `-k` filters work)
- Methodology in `docs/BENCHMARK.md`; results in `docs/BENCHMARK_RESULTS.md`

<!-- MANUAL: -->
> Last updated: uv-based run command, pytest-style note, docs/BENCHMARK.md pointer (commit 8fa2bbf)
