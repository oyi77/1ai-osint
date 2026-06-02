<!-- Generated: 2026-05-31 -->

# 1ai-osint — ZKIT (Zero Knowledge Identity Tracking)

## Purpose
Complete OSINT ecosystem built around Zero Knowledge Identity Tracking (ZKIT). Correlates identities across data sources without requiring prior knowledge of the target. Includes data breach analysis, vulnerability scanning, people/phone finding, identity graph construction, and crypto leak finding with automated sweeping — all as modules within the ZKIT framework.

## Key Files
| File | Description |
|------|-------------|
| `run_scanner.py` | Main entry point — runs the leak scanner pipeline |
| `pyproject.toml` | Project config, dependencies, pytest/ruff settings |
| `PLAN.md` | Original project plan and architecture notes |
| `README.md` | Project overview |
| `Dockerfile` | Container build for deployment |
| `docker-compose.yml` | Multi-service orchestration |
| `scanner.service` | systemd unit for VPS deployment |
| `.env.example` | Environment variable template |
| `.coveragerc` | Coverage configuration |
| `benchmark.py` | Performance benchmarking |
| `demo.sh` | Demo script |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `src/` | Application source code (see `src/AGENTS.md`) |
| `tests/` | Test suites (see `tests/AGENTS.md`) |
| `docs/` | Research papers and protocol docs (see `docs/AGENTS.md`) |
| `scripts/` | Utility scripts (see `scripts/AGENTS.md`) |
| `notebooks/` | Jupyter notebooks for analysis (see `notebooks/AGENTS.md`) |
| `state/` | Runtime state files |
| `.github/` | CI/CD workflows (see `.github/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Python 3.12, pytest for testing, ruff for linting
- Always `rm -f .coverage` before full pytest runs (corruption issue)
- Fix locally first, commit, push — don't SSH repeatedly to VPS
- Never start VPS scanner without user permission

### Testing Requirements
- `pytest` — runs all tests
- `ruff check` — linting
- Keep coverage above 79%

### Common Patterns
- Async-first architecture with httpx and web3.py
- Multi-chain support: EVM, Solana, Bitcoin, Tron, and more
- AI analysis via LLM integration (analyzers + prompts)
- Vendor modules under `src/vendor/` for third-party integrations

## Dependencies

### External
- httpx — async HTTP client
- web3.py — EVM chain interaction
- solders — Solana SDK
- bit — Bitcoin transactions
- pydantic — data models
- pytest — testing framework
- ruff — linter

<!-- MANUAL: -->
