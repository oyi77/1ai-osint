# 1ai-osint: Scanner Throughput Benchmarking & Reproducibility

This document details instructions for running and reproducing the performance benchmark for the ZKIT crypto balance scanner.

## Benchmark Design

The throughput benchmark runs the `RandomScanner` engine for a set duration, checking generated BIP-39 mnemonic phrases against EVM (Ethereum, BSC, Polygon), Solana, and Bitcoin blockchains using public JSON-RPC nodes.

Performance is judged on three metrics:
1. **Throughput (Mnemonics/sec)**: Target >= 20.0 mnemonics/sec.
2. **Addresses/sec**: Derived addresses validated per second across all chains.
3. **API Error Rate**: Percentage of RPC requests returning HTTP/RPC errors. Target <= 10.0%.

## Running the Benchmark

Execute the benchmark utility script:

```bash
python scripts/benchmark.py --duration 60 --workers 20
```

### Options

* `--duration <seconds>`: Duration of the benchmark (default: 60).
* `--workers <count>`: Number of concurrent async workers checking balances (default: 20).

## Reproducibility Package

To verify reproducibility:

1. Clean python cache:
   ```bash
   find . -type d -name "__pycache__" -exec rm -rf {} +
   ```
2. Start the benchmark in a clean environment:
   ```bash
   python scripts/benchmark.py --duration 30 --workers 25
   ```
3. The benchmark will output verification checks (PASS/FAIL) on overall execution throughput.

## Machine-Readable Receipts (v1)

`--json` emits a single JSON receipt on stdout in addition to the human
summary. Receipts are schema-versioned (`1ai-osint.benchmark.receipt.v1`)
and embed everything needed to reproduce or audit a run:

```json
{
  "schema": "1ai-osint.benchmark.receipt.v1",
  "tool": "scripts/benchmark.py",
  "commit": "<git sha at run time>",
  "timestamp_utc": "...",
  "machine": {"machine": "...", "cpu_count": N, "cpu_model": "...",
              "platform": "...", "python": "...", "uv": "..."},
  "params": {"workers": 20, "duration_sec": 60, "chains": [...]},
  "targets": {"mnemonics_per_sec": 20.0, "error_rate_pct_max": 10.0},
  "metrics": {"elapsed_sec": ..., "mnemonics_generated": ..., "addresses_checked": ...,
              "hits_found": ..., "api_errors": ..., "mnemonics_per_sec": ...,
              "addresses_per_sec": ..., "error_rate_pct": ...},
  "verdict": "PASS"
}
```

To produce a receipt and save it as evidence:

```bash
uv run python scripts/benchmark.py --duration 60 --workers 20 --json \
  > docs/evidence/benchmark/receipt_$(date +%F).json
```

### Reading a receipt honestly

The verdict is an **honest snapshot of one run against live public RPC
endpoints**, not a code-quality score. Public nodes throttle and go down,
so an elevated `error_rate_pct` or a `FAIL` verdict is expected from time to
time and documents upstream health, not a regression. When comparing
runs, compare `metrics.mnemonics_per_sec`, `metrics.error_rate_pct`, the
`machine` spec and the `commit` — never just the verdict.

### Reproducing a run

```bash
# Pin to the exact commit that produced a given receipt, then run:
uv sync --group dev --frozen
uv run python scripts/benchmark.py --duration 60 --workers 20 --json
```

The CI `benchmark` workflow (`.github/workflows/benchmark.yml`) runs the same
command on every push touching `src/`, `pyproject.toml`, `uv.lock` or
`scripts/benchmark.py` and uploads the receipt as a build artifact. The job
fails only when no receipt is produced (i.e. the benchmark crashed) — the
verdict itself is never used as a gate.

### Evidence on record

| Date | File | Verdict | Notes |
|------|------|---------|-------|
| 2026-08-01 | `docs/evidence/benchmark/receipt_2026-08-01.json` | FAIL | Smoke run; 12 mnemonics / 0.30 mnemonics/sec, 32.6% API error rate — live public RPC throttling/outage, not a code regression |
