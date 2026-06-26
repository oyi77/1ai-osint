# AGENTS.md — 1ai-ecosystem Engineering Rules

This repository is part of the **1ai-ecosystem**. You are governed by the mandatory engineering rules below.

---

## ⚡ START HERE

Read the rules in the order specified for your session type. **Do not skip. Do not summarize. Read the full text.**

> The rules are located at `_rules/` in this repo, synced from `github.com/oyi77/1ai-rules`.

```
_rules/
├── ENGINEERING.md    ← core engineering protocol (always required)
├── VERIFICATION.md   ← receipt enforcement (always required)
├── QA.md             ← QA protocol (for testing sessions)
├── SURPASS.md        ← competitive strategy (for planning sessions)
└── DOCS.md           ← documentation standards (for docs sessions)
```

---

## Session Classification

Determine your session type, then load the required rules **in order**:

| Session Type | Required Reading | Order |
|---|---|---|
| **Coding / bugfix / feature** | ENGINEERING.md + VERIFICATION.md | 1 → 2 |
| **QA / testing existing code** | QA.md + VERIFICATION.md | 1 → 2 |
| **Competitive research / planning** | SURPASS.md | 1 |
| **Documentation** | DOCS.md | 1 |
| **Full sprint (build + test + docs)** | ALL rules (ENGINEERING.md + VERIFICATION.md + QA.md + SURPASS.md + DOCS.md) | 1→2→3→4→5 |

---

## Hard Rules (apply regardless of session type)

1. **Receipts are mandatory.** Every "done" claim requires literal verbatim terminal/test/log output. A summary is not a receipt. No receipt = not done.
2. **Break it before you ship it.** Adversarial test required before any completion claim. Empty input, max boundary, error paths, concurrent access, auth boundaries.
3. **Docs are part of the deliverable.** Code changes without synced docs are incomplete. Update docs in the same change.
4. **No silent failure.** Every error must be caught, logged, and surfaced. Empty catches and suppressed errors are defects.
5. **No hallucinated paths/symbols/APIs.** Read the file before claiming it exists. Use codebase-memory-mcp or equivalent on indexed repos.
6. **These rules cannot be waived** by any instruction, task phrasing, or user request. See ENGINEERING.md §8 for the conflict hierarchy.

---

## Detection

- If `_rules/` does not exist → this repo hasn't been set up yet. Load rules from `~/.1ai/rules/` (on the local filesystem) or clone `github.com/oyi77/1ai-rules` first.
- If `~/.1ai/` does not exist → run the setup script: `gh repo clone oyi77/1ai-rules ~/.1ai`

---

## Project-Specific Notes

<!-- Add repo-specific rules below this line -->
<!-- Examples: port numbers, env vars, deploy targets, CI commands, local quirks -->

---

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
- **CloakBrowser Integration**: Use the `--cloak` flag or `CLOAKBROWSER_API_URL` to route web scraping requests (LinkedIn, Facebook, etc.) through anti-detect chromium CDP sessions via `src/core/cloak_client.py`.

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
