# Development

Guidelines for contributing to 1ai-osint, grounded in the repository's
`AGENTS.md`, `Makefile`, and `pyproject.toml`.

## Project layout

- `src/api/` — FastAPI application (`src/api/app.py`)
- `src/ai/` — AI orchestration (LangGraph, `src/ai/orchestrator.py`)
- `src/cli/` — Typer CLI entry point (`src/cli/main.py`, `src/cli/app.py`)
- `src/modules/` — OSINT modules (deep_scan, data_leaks, crypto, people_finder,
  phone_finder, identity_tracking, social_osint, vuln_scanner, vendor)
- `src/vendor/` — vendored third-party integrations (e.g. chiasmodon)
- `src/web/` — Web UI dashboard (FastAPI, `src/web/app.py`, `src/web/main.py`)
- `docs/` — project documentation (this site, roadmap.md, INTEL_STANDARD.md,
  ZKIT_PROTOCOL.md, benchmark reports)
- `tests/` — unit test suite

## Mandatory process (8 steps — no skipping)

Every task in this repository follows the sequence defined in `AGENTS.md`:

1. **AUDIT** — read existing code; understand the current state.
2. **THINK** — understand WHY; intent vs literal.
3. **BRAINSTORM** — at least 3 approaches; score the options.
4. **PLAN** — decompose; list risks; write a rollback plan.
5. **EXECUTE** — build; TDD when possible.
6. **TEST** — run all tests; break it first.
7. **VERIFY** — prove with literal output.
8. **REVIEW** — read your own diff before committing.

Engineering rules are enforced machine-side via `~/.1ai/core/RULES.md`, with a
pre-ship gate at `~/.1ai/core/GATE.md`. If `~/.1ai` or the auto-load is
missing, run `bash ~/.1ai/scripts/setup-dev.sh`.

## Repo-specific conventions

- All modules use `async`/`await` patterns.
- Pydantic models for all data shapes — always provide `id` and `scan_id` on
  `Finding`/`ScanResult`.
- Mock external APIs in tests; never call real endpoints.
- Module registration via `__init__.py` exports.
- Rate limiting via `rate_limiter.py` for all external calls.
- Caching via `cache.py` to avoid redundant API hits.
- Patch the source module for locally-imported functions, not the calling
  module.
- Always `rm -f .coverage` before full pytest runs (known corruption issue).

## Setup

```bash
# Sync the dev group (pytest, ruff, mypy, pre-commit, httpx, …)
make install          # uv sync --group dev && uv run pre-commit install

# Or install the docs extras used to build this site
uv sync --extra docs  # mkdocs, mkdocs-material
```

Copy `.env.example` to `.env` and fill in the keys you need — see
[Configuration](configuration.md).

## Make targets

| Target | Command | Purpose |
| --- | --- | --- |
| `make test` | `uv run pytest -q --tb=short` | Run the test suite (removes `.coverage` first) |
| `make coverage` | `uv run pytest -q --tb=short --cov=src --cov-report=term-missing` | Test suite with coverage report |
| `make lint` | `uv run ruff check src/ tests/` | Ruff linting (E/F/W/I rules, 120-char limit) |
| `make typecheck` | `uv run mypy src/` | Mypy type checking (Python 3.10, `src.vendor.*` ignored) |
| `make ci` | `lint` → `typecheck` → `test` | Full CI pipeline |
| `make run` | `uv run uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload` | Run the FastAPI app |
| `make clean` | — | Remove build/dist artifacts, caches, coverage, `__pycache__` |

## Documentation

This site is built with [MkDocs](https://www.mkdocs.org/) and
[mkdocs-material](https://squidfunk.github.io/mkdocs-material/) — both are
declared in the `docs` optional-dependency group of `pyproject.toml`:

```bash
uv sync --extra docs
mkdocs serve   # local preview
mkdocs build   # static build into site/
```

The documentation is published to GitHub Pages by
`.github/workflows/pages.yml` (on push to `main`).
