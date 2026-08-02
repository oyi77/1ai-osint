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
| `deep_scan/` | Multi-source deep scan engine — dossiers, AI briefing, threat modeling (see `deep_scan/AGENTS.md`) |
| `domain_recon/` | Domain reconnaissance — subdomains, tech fingerprinting (see `domain_recon/AGENTS.md`) |
| `email_osint/` | Email OSINT — validation, breach lookup, account discovery (see `email_osint/AGENTS.md`) |
| `entity_timeline/` | Entity timeline — chronological event tracking (see `entity_timeline/AGENTS.md`) |
| `free_intel/` | Keyless free intelligence sources (see `free_intel/AGENTS.md`) |
| `monitoring/` | Target watchlist, change detection, alerting (see `monitoring/AGENTS.md`) |
| `node/` | Distributed node management — master/agent scanning (see `node/AGENTS.md`) |
| `report_engine/` | Formatted intelligence report generation (see `report_engine/AGENTS.md`) |
| `social_osint/` | Social media OSINT — username enumeration, profile scraping (see `social_osint/AGENTS.md`) |
| `vendor/` | Third-party vendor tool adapters — theHarvester, Holehe, etc. (see `vendor/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Each module is self-contained with its own `__init__.py`
- Modules self-register via `src/modules/__init__.py` (`register_module` → `_MODULE_REGISTRY`); CLI commands are wired through `src/cli/` (shared typer app in `src/cli/app.py`)
- Follow existing patterns when adding new modules

> Last updated: completed subdirectory table (10 missing modules); corrected CLI registration path (commit 8fa2bbf)

<!-- MANUAL: -->
