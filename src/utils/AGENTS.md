---
scope: src/utils
depends_on: [src]
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-01 -->

# utils

## Purpose
Shared utility helpers for the package. Currently a single module for Indonesian phone-number normalization and carrier lookup.

## Key Files
| File | Description |
|------|-------------|
| `phone_normalize.py` | Indonesian phone normalization and carrier lookup |

## Exports
| Symbol | Type | Description |
|--------|------|-------------|
| `normalize_phone_e164(value, default_region="ID")` | function | Normalizes a phone number to E.164 (returns `None` when invalid) |
| `ID_CARRIER_PREFIXES` | `dict[str, str]` | 4-digit Indonesian carrier prefixes keyed by operator |
| `lookup_id_carrier(e164)` | function | Returns the carrier for a valid Indonesian E.164 number, else `None` |

## For AI Agents

### Working In This Directory
- Stdlib only — no third-party imports
- No `__init__.py`; the module is imported directly as `src.utils.phone_normalize`

## Issues
- No `__init__.py` in this directory, so there is no `__all__` export surface for tooling.

## Recommendations
- Add an `__init__.py` re-exporting the public functions once a second module is added here.
- Cover `lookup_id_carrier` edge cases (invalid numbers, non-ID regions) with unit tests.

<!-- MANUAL: -->

> Last updated: Initial file (commit 8fa2bbf)
