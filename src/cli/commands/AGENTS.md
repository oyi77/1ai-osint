<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# commands

## Purpose
CLI command implementations — each file provides a group of related typer commands.

## Key Files
| File | Description |
|------|-------------|
| `scan_commands.py` | Scan execution commands |
| `crypto_commands.py` | Crypto OSINT commands |
| `identity_commands.py` | Identity tracking commands |
| `monitor_commands.py` | Watchlist and monitoring commands |
| `config_commands.py` | Configuration management commands |
| `node_commands.py` | Node management commands |

## For AI Agents

### Working In This Directory
- Each command file registers a typer sub-app
- Commands delegate to modules in `src/modules/`

## Dependencies

### Internal
- `src/cli/main.py` — typer app registration
- `src/modules/` — module implementations

<!-- MANUAL: -->
