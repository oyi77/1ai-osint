# 1ai-osint

**One-stop AI-Powered OSINT & ZKIT Research Platform**

> CLI-first security investigation tool combining OSINT aggregator, secret scanner, crypto analyzer, and Zero Knowledge Identity Tracking (ZKIT) — all orchestrated by AI via LangGraph + Omniroute.

## Quick Start

```bash
# Install
pip install -e .

# Run
python -m src.cli --help
```

## Features

| Module | Description |
|--------|-------------|
| **Gitleaks** | Git repo secret scanning (GitHound-based) |
| **Data Leaks** | Breach database aggregation (extends HellCatZ) |
| **People Finder** | Social media username search |
| **Phone Finder** | Phone number OSINT |
| **Crypto Passphrase** | BIP-39 generation + entropy checking |
| **Crypto Private Key** | Leaked key detection + validation |
| **ZKIT Identity** | Privacy-preserving identity correlation |
| **AI Orchestrator** | LangGraph workflow with Omniroute |

## Research

This project accompanies the paper:
> **"Zero Knowledge Identity Tracking (ZKIT): Leveraging AI, OSINT, and Leaked Data for Comprehensive Investigations"**

See `docs/RESEARCH.md` for draft.

## Architecture

```
CLI → LangGraph Orchestrator → [Modules] → ZKIT Engine → Report Generator
         ↕
   Omniroute (160+ LLM providers)
```

## License

MIT