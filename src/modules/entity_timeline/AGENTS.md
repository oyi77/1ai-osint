<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# entity_timeline

## Purpose
Entity timeline — chronological event tracking, timeline building, and visualization for OSINT targets.

## Key Files
| File | Description |
|------|-------------|
| `timeline_builder.py` | Constructs chronological event timelines |
| `timeline_viz.py` | Timeline visualization and rendering |
| `models.py` | Timeline data models |
| `__init__.py` | Package initializer |

## For AI Agents

### Working In This Directory
- Timelines aggregate events across all OSINT modules
- Supports time-series anomaly detection

## Dependencies

### Internal
- `src/core/` — models and data access
- `src/modules/monitoring/` — change detection events

<!-- MANUAL: -->
