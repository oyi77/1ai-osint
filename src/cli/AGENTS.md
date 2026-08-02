---
scope: src/cli
depends_on: [src/core, src/modules, src/cli/commands]
status: complete
---

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# cli

## Purpose
Command-line interface entry point — Typer app, argument parsing, module resolution, and terminal output.

## Key Files
| File | Description |
|------|-------------|
| `main.py` | Console entry (`1ai-osint = src.cli.main:app`); loads `.env`, imports command modules to trigger `@app.command()`, global `--log-format`/`--log-level` callback |
| `app.py` | Shared `typer.Typer` app instance + `SCAN_MODULES` / `OUTPUT_FORMATS` constants |
| `helpers.py` | `get_module()` resolver, `run_with_ai()`, `run_zkit_tracking()`, `init_plugins()`, `_PassphraseModule` adapter |
| `__init__.py` | Package initializer |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `commands/` | CLI command implementations (see `commands/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- One shared `app` from `src.cli.app`; command modules register via `@app.command()` when imported by `main.py`
- Output via `typer.echo`; `rich` used only in `zkit-deep-scan` (progress bar, tables)
- `.env` loaded before any `src.*` import so settings come from the environment
- Sync command functions wrap async work with `asyncio.run(...)`

## Dependencies

### Internal
- `src/core/` — models (`Finding`/`ScanResult`/`Severity`), config, logging, compliance, rbac
- `src/modules/` — module instances via `get_module()`, deep-scan engine, report engine, output (sarif/pdf)
- `src/plugin/` — plugin registry via `init_plugins`
- `src/doctor.py` — `run_doctor`/`format_doctor_report` (used by `config_commands.doctor`)

## Findings
- [Medium] `get_module` alias shadowing (`helpers.py:41` vs `helpers.py:73`) — `"social"` matches the first branch `("people", "people_finder", "social")` and resolves to `PeopleFinderSearch`; the later `("social", "social_osint")` → `SocialOSINTTool` branch is unreachable via `social`. `--module social` runs the wrong tool.
- [Medium] `scan --module all` (`commands/scan_commands.py:70`) runs only gitleaks, data_leaks, people, phone, crypto_privatekey — not the full `SCAN_MODULES` list; `all` is misleading.

> Last updated: added frontmatter, corrected command-registration model (shared app, not per-file sub-apps), added helpers/entry-point details + alias-shadowing and `all`-module findings (commit 8fa2bbf)
