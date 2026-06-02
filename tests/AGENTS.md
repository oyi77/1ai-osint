<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

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
| `unit/` | Unit tests mirroring `src/` structure (see `unit/AGENTS.md`) |
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
- `pytest` to run all tests
- Target: 79%+ coverage
- Tests should be independent and idempotent

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
