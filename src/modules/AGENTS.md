<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# modules

## Purpose
ZKIT module ecosystem — each module is a capability within the Zero Knowledge Identity Tracking framework. The `identity_tracking` module is the core; all other modules feed data into it for correlation and graph analysis.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `base/` | Base classes and shared module infrastructure (see `base/AGENTS.md`) |
| `sources/` | Shared leak sources — GitHub, Reddit, NPM, StackOverflow, etc. (see `sources/AGENTS.md`) |
| `crypto/` | Crypto leak finding, balance checking, sweeping (see `crypto/AGENTS.md`) |
| `data_leaks/` | Data breach and leak aggregation (see `data_leaks/AGENTS.md`) |
| `gitleaks/` | Git secret scanning (see `gitleaks/AGENTS.md`) |
| `identity_tracking/` | Identity correlation and graph analysis (see `identity_tracking/AGENTS.md`) |
| `output/` | Report generation — JSON, PDF, SARIF (see `output/AGENTS.md`) |
| `people_finder/` | People search capabilities (see `people_finder/AGENTS.md`) |
| `phone_finder/` | Phone number lookup (see `phone_finder/AGENTS.md`) |
| `vuln_scanner/` | Vulnerability scanning (see `vuln_scanner/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Each module is self-contained with its own `__init__.py`
- Modules register with the CLI via `src/cli.py`
- Follow existing patterns when adding new modules

<!-- MANUAL: -->
