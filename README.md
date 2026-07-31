# 1ai-osint

**One-stop AI-Powered OSINT & ZKIT Research Platform**

> CLI-first security investigation tool combining OSINT aggregator, secret scanner, crypto analyzer, and Zero Knowledge Identity Tracking (ZKIT) — all orchestrated by AI via LangGraph + Omniroute.

[![CI](https://github.com/openclaw/1ai-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/openclaw/1ai-osint/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Mypy](https://img.shields.io/badge/type%20checked-mypy-blue)](http://mypy-lang.org/)
[![Coverage](https://img.shields.io/badge/coverage-77%25-yellow)](https://coverage.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/openclaw/1ai-osint/releases)

## Quick Start

```bash
# Install with uv (recommended — 10x faster than pip)
uv sync

# Or with pip
pip install -e ".[dev]"

# Configure
cp .env.example .env
# Edit .env with your API keys

# Verify setup
uv run 1ai-osint doctor

# Run a deep scan
uv run 1ai-osint deep-scan "Target Name" --profile fast
uv run 1ai-osint deep-scan user@example.com --profile deep --case INV-001 --pdf
```

## Features

| Module | Description | Status |
|--------|-------------|--------|
| **Gitleaks Scanner** | Git repo secret scanning (GitHound-based) | ✅ Stable |
| **Data Leaks Aggregator** | Breach database aggregation (extends HellCatZ) | ✅ Stable |
| **People Finder** | Social media username search (Sherlock-powered) | ✅ Stable |
| **Phone Finder** | Phone number OSINT with carrier/country lookup | ✅ Stable |
| **Crypto Passphrase** | BIP-39 mnemonic generation + entropy analysis | ✅ Stable |
| **Crypto Private Key** | Leaked private key detection + validation | ✅ Stable |
| **Crypto Balance Checker** | Derive addresses and check on-chain balances | ✅ Stable |
| **ZKIT Identity Graph** | Privacy-preserving identity correlation with co-occurrence | ✅ Stable |
| **Deep Scan Engine** | Multi-phase investigation: name → username → profile → scrape → correlate | ✅ Stable |
| **AI Orchestrator** | LangGraph workflow with Omniroute (160+ LLM providers) | ✅ Stable |
| **CloakBrowser Stealth** | Bypasses CDNs & CAPTCHAs via Chrome DevTools Protocol | ✅ Stable |
| **Web Dashboard** | FastAPI-based results viewer with entity timeline | 🚧 Beta |

## Architecture

```
                          ┌──────────────────────┐
                          │    CLI (Click/Typer)  │
                          └──────┬───────┬───────┘
                                 │       │
                    ┌────────────▼┐  ┌───▼────────────┐
                    │ Plugin System │  │ Deep Scan Engine│
                    │ (Dynamic load)│  │ (Async pipeline)│
                    └──────────────┘  └───┬────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │    LangGraph AI Orchestrator  │
                          │   (AnalysisOrchestrator)      │
                          └───────┬──────────┬───────────┘
                                  │          │
                    ┌─────────────▼──┐  ┌───▼─────────────┐
                    │   Omniroute    │  │  ZKIT Engine     │
                    │ (160+ LLMs)    │  │ (Identity Graph) │
                    └────────────────┘  └─────────────────┘
```

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run all CI checks
make ci

# Or individually
make lint           # ruff check
make typecheck      # mypy
make test           # pytest
make coverage       # pytest + coverage report

# Pre-commit hooks (auto-fix on commit)
uv run pre-commit install
```

### Code standards

- **2160+ tests** — pytest with `pytest.mark.asyncio` for async modules
- **77% coverage** — `--cov=src --cov-fail-under=70`
- **0 mypy errors** — strict-ish config with targeted vendor overrides
- **0 ruff errors** — with `--fix`
- **AGI-friendly** — see [AGENTS.md](AGENTS.md) for our AI coding conventions

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full improvement plan to 10/10.

## Research

This project accompanies the paper:
> **"Zero Knowledge Identity Tracking (ZKIT): Leveraging AI, OSINT, and Leaked Data for Comprehensive Investigations"**

See [docs/RESEARCH.md](docs/RESEARCH.md) for the draft.

## License

MIT
