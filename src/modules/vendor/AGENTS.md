---
scope: vendor
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# vendor

> Last updated: document ExternalToolIntel + mixin line numbers, note chiasmodon consumers (commit 8fa2bbf)

## Purpose
External vendor tool integration — adapters for third-party OSINT and recon tools (theHarvester, Holehe, etc.).

## Key Files
| File | Description |
|------|-------------|
| `external_tools.py` | `ExternalToolIntel` (line 20) — main wrapper combining username/domain/recon mixins |
| `_ext_domain_mixin.py` | `ExternalToolDomainMixin` (line 21) — domain recon utilities |
| `_ext_recon_mixin.py` | `ExternalToolReconMixin` (line 18) — reconnaissance utilities |
| `_ext_username_mixin.py` | `ExternalToolUsernameMixin` (line 22) — username search utilities |
| `__init__.py` | Re-exports the classes above |

## For AI Agents

### Working In This Directory
- Wraps CLI tools (theHarvester, Holehe, etc.) as Python interfaces
- Parses tool output into standard Finding models
- Related vendor code lives in `src/vendor/chiasmodon/` (consumed by `data_leaks`, `phone_finder`, `people_finder`)

## Dependencies

### Internal
- `src/core/` — models, rate limiting, logging

<!-- MANUAL: -->
