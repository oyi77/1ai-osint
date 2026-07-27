<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# plugin

## Purpose
Plugin system — hook-based extensibility for scan lifecycle events and custom logic.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `BasePlugin` abstract base class |
| `registry.py` | `PluginRegistry` — plugin discovery and lifecycle |
| `hooks.py` | `HookDispatcher` — dispatch events to registered plugins |
| `__init__.py` | Public API exports |

## For AI Agents

### Working In This Directory
- Plugins implement `BasePlugin` interface
- Hook system fires events at scan start/complete/error
- Discovered automatically from `src/plugins/`

## Dependencies

### Internal
- `src/core/models.py` — data models used in hook payloads

<!-- MANUAL: -->
