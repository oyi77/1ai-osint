---
scope: src/investigations
depends_on: [src/core/config]
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# investigations

## Purpose
Case management — bundle findings and artifacts into investigation cases with audit trails (timestamped run folders under `investigations/<case_id>/runs/`).

## Key Files
| File | Description |
|------|-------------|
| `case_manager.py` | `CaseManager` — `ensure_case()` (create case), `save_run()` (persist one deep-scan run), `load_previous_intel()` (latest intel for delta comparison), `case_path()` (sanitized path) |
| `__init__.py` | Package initializer — exports `CaseManager` only |

## For AI Agents

### Working In This Directory
- Cases bundle findings across modules for a single target
- Persistence is filesystem JSON under `Settings().project_root / "investigations/<case_id>/"` — **not** `src/core/database.py` (corrected: `case_manager.py:10-19` imports only `src.core.config.Settings`)
- `save_run()` writes `deep_scan.json` (via `to_dict()` duck-typing), `intel.json`, `briefing.html`, `intel.stix.json`, `briefing.pdf`, plus a `latest` pointer file (`case_manager.py:44-77`)
- "Chain of custody" = immutable timestamped run dirs + `case.json` metadata; there is no cryptographic chain-of-custody mechanism — [INFERENSI]
- `load_previous_intel()` returns `None` both for "no case yet" and "no intel.json in latest run" — no distinction (`case_manager.py:79-89`)

## Dependencies

### Internal
- `src/core/config.py` — `Settings.project_root` for the case base directory
- Consumed by: `src/api/app.py`, `src/cli/commands/scan_commands.py`, `src/modules/deep_scan/breach_router.py`, `src/modules/monitoring/watchlist.py`, `src/modules/monitoring/alerter.py`, `src/core/rbac.py`

> Last updated: corrected stale dependency claims (persistence is filesystem, not `src/core/database.py`); documented `save_run` artifacts, `load_previous_intel` semantics, and `__init__.py` exports (commit 8fa2bbf)
