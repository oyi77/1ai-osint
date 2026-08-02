---
scope: src/plugin
depends_on: []
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# plugin

## Purpose
Plugin system — hook-based extensibility for scan lifecycle events and custom logic.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `BasePlugin` abstract base class — `name`/`version`/`description`/`hooks` attrs + no-op `on_scan_start`, `on_scan_end`, `on_report`, `on_error` |
| `registry.py` | `PluginRegistry` — `register()`, `discover()` (scans `src.plugins` package + `1ai_osint.plugins` entry points), `get()`, `list()`, `get_hooks()` |
| `hooks.py` | `HookDispatcher` — `dispatch()` (concurrent, error-isolated) and `dispatch_ordered()` (sequential) |
| `__init__.py` | Public API exports — `BasePlugin`, `HookDispatcher`, `PluginRegistry`, plus `get_dispatcher()` (process-wide lazy singleton) and `reset_plugins()` (test hook) |

## For AI Agents

### Working In This Directory
- Plugins implement `BasePlugin` (abstract — subclasses only override hooks they care about)
- 4 hook events: `on_scan_start(target, module)`, `on_scan_end(result)`, `on_report(report)`, `on_error(error, context)`
- Discovered automatically from `src/plugins/` (module-level `plugin` attribute) and from installed entry points
- Hook payloads are duck-typed (`Any`) — no hard import of `src/core/models.py` (corrected)

## Dependencies

### Internal
- `src/plugin/base.py` ↔ `registry.py` ↔ `hooks.py` — no external runtime deps
- Consumed by: engine/CLI/web layers via `src.plugin.get_dispatcher()`

## Issues
- [Medium] `PluginRegistry.get_hooks()` filters on the `hooks` class attribute — implementing an `on_*` method without listing it in `hooks` silently never fires (`base.py:28`, `registry.py:108-118`). Contract fragility: the list must be manually kept in sync.
- [Low] `dispatch()` uses `asyncio.as_completed`, so results arrive in *completion* order, not the "plugin registration order" claimed in its docstring — only `dispatch_ordered()` guarantees registration order (`hooks.py:41-62` vs `hooks.py:64-82`).

> Last updated: added `get_dispatcher`/`reset_plugins` to exports, corrected hook list (4 events incl. `on_report`), fixed stale `src/core/models.py` dependency claim (commit 8fa2bbf)
