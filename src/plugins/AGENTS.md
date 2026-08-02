---
scope: src/plugins
depends_on: [src/plugin]
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# plugins

## Purpose
Built-in plugin implementations — example plugins and default hook handlers. Each module must expose a module-level `plugin` attribute (a `BasePlugin` instance) to be auto-discovered by `PluginRegistry.discover()` (`registry.py:145`).

## Key Files
| File | Description |
|------|-------------|
| `example_plugin.py` | `ExampleLoggingPlugin` (name `example_logger`, v0.1.0) — logs `on_scan_start`/`on_scan_end`; module-level `plugin` instance at import time |
| `__init__.py` | Package initializer — documents the discovery contract; no exports |

## For AI Agents

### Working In This Directory
- Each file is a standalone plugin class with a top-level `plugin` instance
- Follow `example_plugin.py` patterns when adding new plugins (class attrs `name`/`version`/`description`/`hooks` + async hook methods)
- `hooks` list must match implemented methods or the plugin will never be dispatched (see `src/plugin/AGENTS.md`)

## Dependencies

### Internal
- `src/plugin/base.py` — `BasePlugin` base class
- `src/plugin/registry.py` — plugin discovery/registration

## Issues
- [Low] `example_plugin.py:27,37` uses `print()` alongside `logger` — output leaks to stdout in server contexts; cosmetic for an example.

> Last updated: documented the module-level `plugin` discovery contract and current plugin metadata (commit 8fa2bbf)
