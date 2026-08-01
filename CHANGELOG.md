# Changelog

All notable changes to 1ai-osint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 5 new keyless RE-first sources (0-API priority): hackertarget hostsearch/reverse-IP, Google DoH DNS records, mempool.space, ip-api.com, keys.openpgp.org PGP lookup
- 0-API mode registry now reports 93 sources / 79 keyless-capable / 73 keyless-only
- AI analysis pipeline: LangGraph orchestrator with entity extraction, correlation, risk scoring
- Behavioral profiling and anomaly detection modules
- Continuous monitoring subsystem: watchlist, change detection, alert dispatch
- Plugin system with auto-discovery via entry points and pkgutil
- Web dashboard: FastAPI routes for entities, timeline, reports
- Entity timeline builder with snapshot diff visualization
- Stealth browser scraping: CloakBrowser CDP + local Playwright fallback
- Comprehensive mypy type coverage (zero errors)
- Ruff lint enforcement (zero errors)

### Changed
- Full ruff lint fix: 177 auto-fixed, 6 manually resolved
- Pre-commit hooks installed (ruff, format, YAML, whitespace checks)
- Mypy config added to pyproject.toml with typed package marker
- All `__init__.py` stubs filled with descriptive docstrings
- AGENTS.md placeholders filled with domain/conventions
- CI coverage threshold raised from 70% to 77%

### Fixed
- 194 mypy type errors resolved across 58 source files
- 4 unused `# type: ignore` comments removed
- Orchestrator PipelineState type compatibility with LangGraph

## [0.1.0] - 2026-05-28

### Added
- Initial release
- OSINT aggregation: breach data, secret scanning, crypto analysis
- ZKIT (Zero Knowledge Identity Tracking) engine
- CLI-first interface with Typer
- OmniRoute AI provider integration
- Docker deployment support
- Benchmark suite for hash throughput and batch ingestion
