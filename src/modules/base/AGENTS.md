<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# base

## Purpose
Base classes and shared infrastructure for all feature modules.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | Abstract base class for modules — defines common interface |

## For AI Agents

### Working In This Directory
- `BaseOSINTTool` (in `base.py`) is an ABC with abstract `search`/`scan`/`analyze`/`learn`
- `hash_identity()` hashes PII for identity fields; `to_zkit_node()` emits `ZKITNode` records
- Finding/ScanResult models come from `src/core/models.py`
- All feature modules inherit from the base class here — changes affect every module

> Last updated: documented verified `base.py` interface — ABC methods, `hash_identity`, `to_zkit_node` (commit 8fa2bbf)

<!-- MANUAL: -->
