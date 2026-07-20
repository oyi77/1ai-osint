# CODEBASE.md — 1ai-osint
> Auto-generated codebase memory for AI agents. Last updated: 2026-06-19.

## Purpose
AI-powered OSINT & Zero Knowledge Identity Tracking (ZKIT) research platform. CLI-first security investigation tool that aggregates breach data, secret scanning, crypto analysis, and identity correlation, orchestrated by AI via LangGraph + OmniRoute.

## Tech Stack
- **Languages**: Python 3.10+
- **Frameworks**: Typer (CLI), FastAPI (API), LangGraph (AI orchestration)
- **Key Libraries**: httpx, pydantic, openai, web3, eth-account, solana, telethon, playwright, sherlock-project, reportlab, bip-utils

## Entry Points
- **CLI**: `src/cli/main.py` → `1ai-osint` command (typer app)
- **API**: `src/api/app.py` → FastAPI server
- **AI Orchestrator**: `src/ai/orchestrator.py` → LangGraph workflow

## Directory Structure
```
src/
  cli/              CLI commands (typer app: deep-scan, doctor, etc.)
  core/             Shared infra: config, cache, database, logging, rate limiter, CloakBrowser client
  ai/               AI orchestration: LangGraph workflows, OmniRoute client, analyzers, prompts
  modules/          OSINT modules: gitleaks, people_finder, phone_finder, crypto, identity_tracking, social_osint, vuln_scanner
  api/              FastAPI REST server with templates
  investigations/   Case management for investigations
  utils/            Phone normalization, helpers
  vendor/           Vendored deps (chiasmodon)
docs/               Research papers, roadmap, ZKIT protocol spec, benchmarks
notebooks/          Jupyter notebooks for analysis and experiments
scripts/            Demo scripts, benchmarks, node installer
tests/              pytest suite (unit, integration, benchmarks, fixtures)
frontend/           React + Vite frontend (optional UI)
output/             Scan output (HTML/JSON reports)
```

## Key Files
| File | Purpose |
|------|---------|
| `src/cli/main.py` | Main CLI entry point — deep-scan, doctor, all subcommands |
| `src/ai/orchestrator.py` | LangGraph workflow orchestrator |
| `src/ai/omniroute_client.py` | OmniRoute LLM gateway client (160+ providers) |
| `src/core/config.py` | Pydantic settings from .env |
| `src/core/database.py` | SQLite/aiosqlite data layer |
| `src/core/cloak_client.py` | CloakBrowser stealth CDP client |
| `src/modules/identity_tracking/` | ZKIT privacy-preserving identity correlation |
| `src/doctor.py` | Dependency and config health checker |
| `docs/ZKIT_PROTOCOL.md` | ZKIT protocol specification |
| `docs/INTEL_STANDARD.md` | Intel briefing structure standard |

## Architecture
```
CLI (typer) → LangGraph Orchestrator → [OSINT Modules] → ZKIT Engine → Report Generator
                      ↕
              OmniRoute (160+ LLM providers)
```
Modules are pluggable: gitleaks, data leaks, people finder, phone finder, crypto passphrase/key scanner, ZKIT identity, CloakBrowser stealth. Results flow through AI orchestrator for analysis and correlation.

## Run Commands
```bash
pip install -e ".[dev]"
cp .env.example .env
1ai-osint doctor                          # check deps
1ai-osint deep-scan "Target" --profile fast --cloak
1ai-osint deep-scan user@example.com --profile deep --case INV-001 --pdf
python -m src.cli.main --help
pytest tests --cov=src
ruff check src tests
```

## Environment Variables
Key vars from `.env.example`:
- `OMNIRoute_BASE_URL`, `OMNIRoute_API_KEY` — OmniRoute AI gateway
- `OPENAI_API_KEY` — direct OpenAI fallback
- `HIBP_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY` — breach/vuln sources
- `GITHUB_TOKEN` — gitleaks scanning
- `ZKIT_SALT` — per-investigation identity hashing salt
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` — alert delivery
- `LOG_LEVEL`, `CACHE_DIR` — runtime settings
