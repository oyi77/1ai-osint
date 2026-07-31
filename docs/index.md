# 1ai-osint

One-stop **AI-Powered OSINT & ZKIT Research Platform**.

![CI](https://img.shields.io/github/actions/workflow/status/oyi77/1ai-osint/ci.yml?branch=main)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Ruff](https://img.shields.io/badge/Ruff-ok-green.svg)
![Mypy](https://img.shields.io/badge/Mypy-ok-green.svg)
![Coverage](https://img.shields.io/badge/Coverage-77%25-green.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)

An AI-powered OSINT & Zero Knowledge Identity Tracking (ZKIT) research
platform. It combines 13+ breach/leak data sources, deep recursive identity
investigations, crypto forensics (passphrase / private-key / balance scanning
across BTC, ETH, SOL, TRON), privacy-preserving ZKIT identity hashing, and an
optional LangGraph AI orchestrator reachable through 160+ LLMs via OmniRoute.

!!! warning "Legal use only"

    This platform is intended for authorized security research, penetration
    testing, and legitimate investigations only. You are responsible for
    complying with all applicable laws and regulations.

## Features

| Feature | Status |
| --- | --- |
| Gitleaks Scanner | ✅ Stable |
| Data Leaks Aggregator (13+ breach sources) | ✅ Stable |
| People Finder (Sherlock-powered) | ✅ Stable |
| Phone Finder | ✅ Stable |
| Crypto Passphrase BIP-39 | ✅ Stable |
| Crypto Private Key Derivation | ✅ Stable |
| Crypto Balance Scanner (BTC/ETH/SOL/TRON) | ✅ Stable |
| ZKIT Privacy-Preserving Identity Tracking | ✅ Stable |
| Deep Scan Engine (recursive, multi-profile) | ✅ Stable |
| Web UI Dashboard (FastAPI) | ⚠️ Beta |
| AI Orchestrator (LangGraph + OmniRoute) | 🚧 Active development |

## Quick start

```bash
# Install with uv (recommended)
uv sync

# ...or with pip
pip install -e ".[dev]"

# Copy the environment template and fill in your API keys
cp .env.example .env

# Run the environment doctor
uv run 1ai-osint doctor

# Run a fast deep scan
uv run 1ai-osint deep-scan "Target Name" --profile fast

# Run a deep scan with case persistence and PDF briefing
uv run 1ai-osint deep-scan "Target Name" --profile deep --case INV-001 --pdf
```

## Documentation

- [Getting Started](getting-started.md) — installation and first scan
- [Architecture](architecture.md) — design overview
- [Modules](modules.md) — available OSINT modules
- [CLI](cli.md) — command reference
- [Web UI](web-ui.md) — dashboard and API
- [Configuration](configuration.md) — environment variables
- [References](references.md) — tools, services, and collections
- [Roadmap](roadmap.md) — project master plan
- [Development](development.md) — contributing and quality gates

## License

MIT — see the repository `LICENSE` file.
