---
scope: entity_timeline
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# entity_timeline

> Last updated: drop unverified time-series anomaly claim, document builder internals (commit 8fa2bbf)

## Purpose
Entity timeline — chronological event tracking, timeline building, and visualization for OSINT targets.

## Key Files
| File | Description |
|------|-------------|
| `timeline_builder.py` | `TimelineBuilder` (line 46, 419 lines) — constructs chronological event timelines; module singleton `BUILDER` (line 419) |
| `timeline_viz.py` | `TimelineVizData` (line 21) — timeline visualization data model |
| `models.py` | `TimelineEvent` (line 12), `EntitySnapshot` (line 25), `Timeline` (line 44) |
| `__init__.py` | Re-exports `EntitySnapshot`, `Timeline`, `TimelineBuilder`, `TimelineEvent`, `TimelineVizData` |

## For AI Agents

### Working In This Directory
- Timelines aggregate events across all OSINT modules
- `TimelineBuilder` normalizes risk levels (`_risk_level_to_score`) and picks event timestamps (`_pick_timestamp`)

## Dependencies

### Internal
- `src/core/` — models and data access
- `src/modules/monitoring/` — change detection events

<!-- MANUAL: -->
