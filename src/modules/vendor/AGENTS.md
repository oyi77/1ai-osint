<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# vendor

## Purpose
External vendor tool integration — adapters for third-party OSINT and recon tools (theHarvester, Holehe, etc.).

## Key Files
| File | Description |
|------|-------------|
| `external_tools.py` | External tool execution and output parsing |
| `_ext_domain_mixin.py` | Domain recon mixin utilities |
| `_ext_recon_mixin.py` | Reconnaissance mixin utilities |
| `_ext_username_mixin.py` | Username search mixin utilities |
| `__init__.py` | Package initializer |

## For AI Agents

### Working In This Directory
- Wraps CLI tools (theHarvester, Holehe, etc.) as Python interfaces
- Parses tool output into standard Finding models

## Dependencies

### Internal
- `src/core/` — models, rate limiting, logging

<!-- MANUAL: -->
