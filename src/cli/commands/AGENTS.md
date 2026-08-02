---
scope: src/cli/commands
depends_on: [src/cli/app, src/modules]
status: complete
---

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# commands

## Purpose
CLI command implementations — every file imports the shared `app` from `src.cli.app` and registers commands via `@app.command()`.

## Key Files
| File | Commands | Description |
|------|----------|-------------|
| `scan_commands.py` | `scan`, `deep_scan`, `report`, `report_from_file`, `zkit-deep-scan` | Scan execution, deep scan, report generation |
| `crypto_commands.py` | `leak_finder`, `sweep` | Crypto leak discovery and wallet sweeping |
| `identity_commands.py` | `resolve` | Identity resolution across sources |
| `monitor_commands.py` | `monitor` | Continuous identity/leak monitoring |
| `config_commands.py` | `version`, `doctor`, `modules`, `plugins`, `install`, `web` | Config, env checks, plugin management, web server |
| `node_commands.py` | `node`, `master` | Worker node / master bot over Telegram |

## For AI Agents

### Working In This Directory
- All commands share ONE typer app from `src/cli/app.py` — there are no per-file sub-apps; `main.py` imports these modules only to trigger registration
- Commands delegate to modules in `src/modules/` via `get_module()` or direct imports
- `monitor` and `leak_finder --continuous` are long-running loops that never exit on their own

## Dependencies

### Internal
- `src/cli/app.py` — shared typer app, `SCAN_MODULES`, `OUTPUT_FORMATS`
- `src/cli/helpers.py` — `get_module`, `run_with_ai`, `run_zkit_tracking`, `init_plugins`
- `src/modules/` — module implementations (crypto, deep_scan, leak_finder, node, report_engine, output)
- `src/core/` — compliance/RBAC gates (`identity_commands`, `monitor_commands`), models

## Findings
- [Medium] Secrets on the command line — `sweep` takes `--key`/`--mnemonic` (`crypto_commands.py:109-110`), visible in the process list (`ps`), plus partial key material echoed to the terminal (`crypto_commands.py:156,165`). Prefer stdin/getpass-style input.
- [Medium] `resolve`/`monitor` hardcode the requester tier as `AccessTier.ADMIN` (`identity_commands.py:53`, `monitor_commands.py:51`) — the CLI always self-grants ADMIN; the tier gate only filters sources by config, not a real caller identity. [INFERENSI] acceptable for a trusted local CLI, but conflicts with RBAC intent.
- [Low] `deep_scan` writes to relative `output/` (`scan_commands.py:214`); a custom `--output` path in another directory is not created → `open()` fails.
- [Low] Magic timeout sentinel — `eff_timeout = float(timeout) if timeout != 30 else prof.timeout_per_module` (`scan_commands.py:174`): an explicit `--timeout 30` is silently ignored.
- [Low] `node status` calls the private `agent._get_status()` (`node_commands.py:44`).
- [Low] `monitor` dedup uses built-in `hash(leak.text[:500])` (`monitor_commands.py:69`) — per-process salt; fine in-process, not persisted.

> Last updated: added frontmatter, corrected "sub-app" description to shared-app registration, documented real command surface per file + secret-in-argv and ADMIN-tier findings (commit 8fa2bbf)
