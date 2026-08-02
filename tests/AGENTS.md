<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 -->

# tests

## Purpose
Test suite for the entire project. Unit tests, fixtures, and performance benchmarks.

## Key Files
| File | Description |
|------|-------------|
| `conftest.py` | Shared pytest fixtures and configuration |
| `test_dynamic_discovery.py` | Dynamic module discovery tests |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `unit/` | Unit tests mirroring `src/` structure — ~131 `test_*.py` files (see `unit/AGENTS.md`) |
| `integration/` | Integration tests — `test_api.py`, `test_deep_scan_golden.py` |
| `fixtures/` | Shared test data and mock responses (see `fixtures/AGENTS.md`) |
| `benchmarks/` | Performance benchmarks (see `benchmarks/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Always `rm -f .coverage` before full pytest runs — known corruption issue
- Test files follow `test_<module>.py` naming
- Mock all external API calls — never hit real endpoints
- Patch source module for locally-imported functions, not calling module
- For EVM: mock `multicall.batch_check_balances`, not `check_balance`
- Always provide `id`/`scan_id` on Finding/ScanResult in test fixtures
- Grep for existing test class names before adding new ones to avoid shadowing

### Testing Requirements
- `make test` (or `uv run pytest`) to run all tests; `make coverage` for coverage report (`--cov=src`)
- Coverage: README badges cite ~77% current (README claims a `--cov-fail-under=70` gate, but the Makefile `coverage` target has no fail threshold); roadmap targets ≥80% per module — keep this consistent across docs
- Tests should be independent and idempotent

### CI Workflows
- Actual workflows in `.github/workflows/`: `ci.yml`, `benchmark.yml`, `soak.yml`, `docs-sync.yml`, `pages.yml`, `release.yml`
- `.github/workflows/AGENTS.md` Key Files table is stale — lists only `ci.yml` + `soak.yml`; do not trust it until regenerated

### Common Patterns
- Async tests with `pytest-asyncio`
- `MagicMock` for API clients, `AsyncMock` for async methods
- Fixtures in `conftest.py` and `fixtures/` directory

## Dependencies

### Internal
- All test files import from `src/`

### External
- pytest
- pytest-asyncio
- pytest-cov

<!-- MANUAL: -->
> Last updated: added integration/ subdir, fixed coverage target, noted stale .github/workflows/AGENTS.md (commit 8fa2bbf)
