# AGENTS.md — 1ai-osint

## MANDATORY PROCESS (8 Steps — No Skipping)

Every task follows this sequence. No exceptions.

1. **AUDIT** — Read existing code. Understand current state.
2. **THINK** — Understand WHY. Intent vs literal.
3. **BRAINSTORM** — ≥3 approaches. Score options.
4. **PLAN** — Decompose. Risks. Rollback plan.
5. **EXECUTE** — Build. TDD when possible.
6. **TEST** — Run all tests. Break it first.
7. **VERIFY** — Prove with literal output.
8. **REVIEW** — Read your own diff before committing.

Full details: `~/.1ai/core/PROCESS.md` (auto-injected by hooks)

## This repo
AI-powered OSINT & ZKIT research platform — breach aggregation, secret scanning, crypto analysis, identity correlation, and AI orchestration.
Stack: Python
Domain: Security intelligence, OSINT, crypto forensics, identity tracking

## Rules — thin loader, no submodule
Rules are NOT vendored into this repo. This repo does NOT need a rules submodule.
`AGENTS.md` is only the repo-local loader: domain, commands, conventions, and pointers to `~/.1ai`.

Engineering rules are enforced by machine-level loaders when `setup-dev.sh` has been run:
- Claude Code: SessionStart hook injects `~/.1ai/core/RULES.md`
- OpenCode: plugin injects `~/.1ai/core/RULES.md`
- OMP: wrapper appends `~/.1ai/core/RULES.md` to launch sessions

Primary rules file:
```bash
cat ~/.1ai/core/RULES.md
```

Pre-ship gate:
```bash
cat ~/.1ai/core/GATE.md
```

If `~/.1ai` or auto-load is missing, run:
```bash
bash ~/.1ai/scripts/setup-dev.sh
```

Do NOT add the rules repo as a git submodule. Update rules centrally, then run/sync the thin `AGENTS.md` template.

## Hard rules
1. Read code before writing code.
2. No completion claim without literal receipt.
3. Compile/test/use like a real user before claiming work is ready.
4. Task must match this repo domain.
5. Run GATE.md before commit/PR.

## Repo-specific conventions
- All modules use async/await patterns
- Pydantic models for all data shapes — always provide `id` and `scan_id` on Finding/ScanResult
- Mock external APIs in tests, never call real endpoints
- Module registration via `__init__.py` exports
- Rate limiting via `rate_limiter.py` for all external calls
- Caching via `cache.py` to avoid redundant API hits
- Patch source module for locally-imported functions, not calling module
- Always `rm -f .coverage` before full pytest runs (known corruption issue)

## Commands
- Dev:   `uv run python -m app`
- Test:  `make test`
- CI:    `make ci` (lint → typecheck → test)
- Lint:  `make lint`
- Type:  `make typecheck`
- Coverage: `make coverage`
