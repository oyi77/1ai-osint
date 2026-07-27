<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# cli

## Purpose
Command-line interface entry point — argument parsing, command routing, and terminal output formatting.

## Key Files
| File | Description |
|------|-------------|
| `main.py` | CLI entry point using typer |
| `app.py` | Application CLI configuration |
| `helpers.py` | Shared CLI utility functions |
| `__init__.py` | Package initializer |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `commands/` | CLI command implementations (see `commands/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Uses `typer` for CLI argument handling
- Commands registered in `main.py`
- Output formatting uses `rich` for tables and colors

## Dependencies

### Internal
- `src/core/` — models, config
- `src/modules/` — module invocation via CLI

<!-- MANUAL: -->
