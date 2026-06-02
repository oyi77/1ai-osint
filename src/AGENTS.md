<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# src

## Purpose
Application source code. Contains the AI analysis layer, feature modules (crypto, leaks, identity, etc.), and vendored third-party integrations.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package root |
| `cli.py` | CLI entry point and argument parsing |
| `config.py` | Configuration loading and management |
| `models.py` | Core Pydantic data models |
| `database.py` | Database operations and persistence |
| `cache.py` | Caching layer |
| `rate_limiter.py` | Rate limiting for API calls |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `ai/` | AI analysis layer — orchestrator, analyzers, prompts, schemas (see `ai/AGENTS.md`) |
| `modules/` | Feature modules — crypto, leaks, identity, output (see `modules/AGENTS.md`) |
| `vendor/` | Third-party integrations (see `vendor/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- All modules use async/await patterns
- Pydantic models in `models.py` — always provide `id` and `scan_id` on Finding/ScanResult
- Config loaded from `.env` — see `.env.example` for required vars

### Testing Requirements
- Tests mirror structure under `tests/unit/`
- Mock external APIs, never call real endpoints in tests

### Common Patterns
- Module registration via `__init__.py` exports
- Rate limiting via `rate_limiter.py` for all external calls
- Caching via `cache.py` to avoid redundant API hits

## Dependencies

### Internal
- Each module imports from `src/models.py` and `src/config.py`

### External
- pydantic — data validation
- httpx — async HTTP
- web3 — EVM chains

<!-- MANUAL: -->
