<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# investigations

## Purpose
Case management — bundle findings and artifacts into investigation cases with audit trails.

## Key Files
| File | Description |
|------|-------------|
| `case_manager.py` | Case lifecycle management — create, update, close cases |
| `__init__.py` | Package initializer |

## For AI Agents

### Working In This Directory
- Cases bundle findings across modules for a single target
- Supports evidence chain of custody tracking

## Dependencies

### Internal
- `src/core/database.py` — case persistence
- `src/core/models.py` — Finding, ScanResult data models

<!-- MANUAL: -->
