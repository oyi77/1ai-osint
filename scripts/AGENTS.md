<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-01 -->

# scripts

## Purpose
Utility scripts for benchmarking, demonstrations, and infrastructure soak testing.

## Key Files
| File | Description |
|------|-------------|
| `benchmark.py` | Performance benchmarking script |
| `demo.sh` | Demo/shell script |
| `soak.py` | Network-free soak test of `RateLimiter` + `Cache` (receipt schema `1ai-osint.soak.receipt.v1`) |
| `live_benchmark.py` | Live side-by-side OSINT tool benchmark (receipt schema `1ai-osint.live-benchmark.receipt.v1`) |

## For AI Agents

### Working In This Directory
- Scripts are standalone utilities, not part of the main application
- Run with `python scripts/benchmark.py` or `bash scripts/demo.sh`
- Run a soak with `uv run python scripts/soak.py --duration 60 --json > receipt.json 2> report.txt`; writes only to temp dirs, never to `.osint_rate_limit.json`/`.osint_cache`
- Detect which external OSINT tools are installed with `uv run python scripts/live_benchmark.py --target testuser --json > receipt.json 2> report.txt` (network-free); add `--mode live` (network + API keys) to actually run the tools against an authorized target, and `--scorecard <path>` to write a markdown comparison

<!-- MANUAL: -->
