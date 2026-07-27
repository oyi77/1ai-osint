<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# core

## Purpose
Core infrastructure — configuration management, caching, rate limiting, data models, and shared utilities used by all modules.

## Key Files
| File | Description |
|------|-------------|
| `config.py` | Pydantic Settings — env-based configuration (`Settings`) |
| `models.py` | Shared Pydantic models — `Finding`, `ScanResult`, `Identity`, `Severity`, `BreachRecord` |
| `database.py` | SQLite persistence layer (`Database`) |
| `cache.py` | Filesystem-based caching (`Cache`) |
| `rate_limiter.py` | Per-domain rate limiting (`RateLimiter`) |
| `cloak_client.py` | Anti-detection browser scraper (`CloakScraper`) |
| `logging_config.py` | Structured JSON logging (`JSONFormatter`, `setup_logging`) |

## For AI Agents

### Working In This Directory
- No hardcoded secrets — all config via `Settings` + `.env`
- All external requests go through `RateLimiter`
- Models in `models.py` are the single source of truth for data shapes

## Dependencies

### External
- pydantic / pydantic-settings — configuration and data validation
- httpx — async HTTP client
- Playwright — headless browser automation

<!-- MANUAL: -->
