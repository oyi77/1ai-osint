---
scope: src/core
depends_on: []
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# core

## Purpose
Core infrastructure — configuration management, caching, rate limiting, data models, compliance, RBAC, and shared utilities used by all modules.

## Key Files
| File | Description |
|------|-------------|
| `config.py` | Pydantic Settings — env-based configuration (`Settings`) |
| `models.py` | Shared Pydantic models — `Finding`, `ScanResult`, `Identity`, `Severity`, `BreachRecord` |
| `database.py` | SQLite/Postgres persistence layer (`Database`) |
| `cache.py` | Filesystem-based caching (`Cache`) |
| `rate_limiter.py` | Per-domain rate limiting (`RateLimiter`, `RequestLimiter`) |
| `cloak_client.py` | Anti-detection browser scraper (`CloakScraper`) |
| `logging_config.py` | Structured JSON logging (`JSONFormatter`, `setup_logging`) |
| `compliance.py` | Legal/consent compliance, source tiers, audit log (`SourceCompliance`, `LegalBasis`, `AuditEntry`, `record_audit`, `registered_sources`) |
| `rbac.py` | Access tier enforcement (`AccessTier`, `tier_for_token`, `tiers_from_env`) |
| `source_registry.py` | Source capability registry (`SourceEntry`, `TransportKind`, `kind_of`, `can_run_keyless`, `keyless_source_names`) |
| `ssrf_guard.py` | SSRF protection for scan targets (`validate_scan_target`) |
| `tos_guard.py` | Terms-of-service gating for external calls (`tos_allows`, `reset_guard`) |

## For AI Agents

### Working In This Directory
- No hardcoded secrets — all config via `Settings` + `.env`
- All external requests go through `RateLimiter`
- Models in `models.py` are the single source of truth for data shapes
- External scan targets pass through `ssrf_guard.validate_scan_target`; `tos_guard.tos_allows` gates external calls

## Dependencies

### External
- pydantic / pydantic-settings — configuration and data validation
- httpx — async HTTP client
- Playwright — headless browser automation

<!-- MANUAL: -->

> Last updated: added frontmatter; added compliance.py, rbac.py, source_registry.py, ssrf_guard.py, tos_guard.py to Key Files (commit 8fa2bbf)
