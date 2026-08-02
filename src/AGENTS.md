---
scope: src
depends_on: []
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# src

## Purpose
Application source code. Contains the AI analysis layer, feature modules (crypto, leaks, identity, etc.), and vendored third-party integrations.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package root — exposes `__version__` (via `importlib.metadata`) |
| `doctor.py` | Health checks — `CheckResult` dataclass, `run_doctor()`, `format_doctor_report()` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `ai/` | AI analysis layer — orchestrator, analyzers, prompts, schemas (see `ai/AGENTS.md`) |
| `api/` | API layer (see `api/AGENTS.md`) |
| `cli/` | CLI entry point and argument parsing (see `cli/AGENTS.md`) |
| `core/` | Core infrastructure — config, models, database, cache, rate limiting, compliance, RBAC (see `core/AGENTS.md`) |
| `investigations/` | Investigation workflows (see `investigations/AGENTS.md`) |
| `mcp_bridge/` | MCP server bridge (`__init__.py`, `server.py`) |
| `modules/` | Feature modules — crypto, leaks, identity, output (see `modules/AGENTS.md`) |
| `plugin/` | Plugin system (see `plugin/AGENTS.md`) |
| `plugins/` | Bundled plugins (see `plugins/AGENTS.md`) |
| `utils/` | Shared helpers — phone normalization (see `utils/AGENTS.md`) |
| `vendor/` | Third-party integrations (see `vendor/AGENTS.md`) |
| `web/` | Web layer (see `web/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- All modules use async/await patterns
- Pydantic models in `core/models.py` — always provide `id` and `scan_id` on Finding/ScanResult
- Config loaded from `.env` — see `.env.example` for required vars

### Testing Requirements
- Tests mirror structure under `tests/unit/`
- Mock external APIs, never call real endpoints in tests

### Common Patterns
- Module registration via `__init__.py` exports
- Rate limiting via `core/rate_limiter.py` for all external calls
- Caching via `core/cache.py` to avoid redundant API hits

## Dependencies

### Internal
- Subpackages import from `src/core/models.py` and `src/core/config.py`

### External
- pydantic — data validation
- httpx — async HTTP
- web3 — EVM chains

<!-- MANUAL: -->

> Last updated: added frontmatter; Key Files now only `__init__.py` + `doctor.py` (config/models/database/cache/rate_limiter moved to `src/core/`); added subdirectories api/, cli/, core/, investigations/, mcp_bridge/, plugin/, plugins/, utils/, web/; internal deps point to `src/core/` (commit 8fa2bbf)
