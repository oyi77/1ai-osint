---
scope: data_leaks
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# data_leaks

> Last updated: document provider list, dedup/false-positive filtering, and severity flow (commit 8fa2bbf)

## Purpose
Data breach and leak aggregation — checks credentials and emails against known breach databases.

## Key Files
| File | Description |
|------|-------------|
| `aggregator.py` | `DataLeaksAggregator` (line 12) — thread-pool provider search, dedup (`email|username:source`), `_filter_false_positives`; CRITICAL/HIGH → Finding confidence 0.85, tags `[breach, leak, source]` |
| `breach_checker.py` | `BreachChecker` (line 38), `BlindQueryResolver` (line 84), `_DATA_CLASS_WEIGHTS` (line 8) — severity scoring |

## For AI Agents

### Working In This Directory
- Providers (imported lazily from `src/vendor/chiasmodon/`, each guarded by try/except ImportError): HIBPTool, LeakCheckTool, ScyllaTool, BreachDirectoryTool, SnusbaseTool, IntelXTool — so provider availability is host-dependent
- API keys read from env vars (e.g. `HIBP_API_KEY`, `LEAKCHECK_API_KEY`, `SCYLLA_API_KEY`, `SNUSBASE_API_KEY`, `INTELX_API_KEY`) — never hardcode values
- Tests: `tests/unit/test_data_leaks.py`, `tests/unit/test_data_leaks_extra.py`

## Dependencies

### Internal
- `src/core/` — models, rate limiting
- `src/vendor/chiasmodon/` — breach data sources

<!-- MANUAL: -->
