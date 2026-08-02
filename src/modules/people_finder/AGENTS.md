---
scope: people_finder
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# people_finder

> Last updated: document tool wrapper + chiasmodon provider search internals (commit 8fa2bbf)

## Purpose
People search capabilities — finds social media profiles of individuals from public sources.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | `PeopleFinderTool` (line 13, 69 lines) — thin wrapper; delegates `scan()` to `PeopleFinderSearch`, `_pick_tool()` probes sherlock/maigret on PATH |
| `search.py` | `PeopleFinderSearch` (line 30) — wraps `src.vendor.chiasmodon` sherlock/maigret/whatsmyname providers (guarded by `shutil.which`); name-pivot via `primary_username_for_name`; dedup (`_deduplicate_profiles`) and confidence scoring (`_score_confidence`: 1 provider 0.5, 2 → 0.75, 3+ → 0.9); `_CONFIDENCE_THRESHOLD = 0.3` |

## For AI Agents

### Working In This Directory
- Requires sherlock/maigret (or the chiasmodon-backed providers) available on the host
- `scan()` pivots multi-word targets through `src.modules.deep_scan.name_pivots.primary_username_for_name`
- Tests: `tests/unit/test_people_finder.py`, `tests/unit/test_people_finder_tool.py`

## Dependencies

### Internal
- `src/core/` — models
- `src/vendor/chiasmodon/` — profile search providers
- `src/modules/deep_scan/` — name-pivot helper

<!-- MANUAL: -->
