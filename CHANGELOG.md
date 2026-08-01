# Changelog

All notable changes to 1ai-osint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Breadth audit: `docs/evidence/BREADTH_AUDIT.md` — category coverage matrix vs Sherlock/Maigret/Holehe/theHarvester/SpiderFoot baselines; P1 gaps (keyless breach corpus, phone RE, username breadth)
- 5 new keyless RE-first sources: bgpview (IP→ASN/prefix/RIR), certspotter (CT-log subdomains), rapiddns (subdomain index), anubis (jldc.me subdomains), urlscan (domain search)
- 3 new keyless RE-first sources (P1-gap closures): proxynova (breach/paste combine), veriphone (phone carrier/line-type), keybase (username profile)
- P2: whatsmyname keyless username presence-echo scrape wired into the deep scan engine as an in-process source (weak-signal heuristic, documented)
- 5 new keyless RE-first sources (0-API priority): hackertarget hostsearch/reverse-IP, Google DoH DNS records, mempool.space, ip-api.com, keys.openpgp.org PGP lookup
- 0-API mode registry now reports 101 sources / 87 keyless-capable / 81 keyless-only
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
