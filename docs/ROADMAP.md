# 1ai-osint — MASTER PLAN
## Road to World-Class Intelligence, Recon & Tracking Platform

> **Vision:** Build the most comprehensive, production-grade, open-source OSINT & intelligence platform — capable of standing side by side with CIA/FBI-grade tooling. Continuously maintained, architecturally sound, and always evolving.

---

## Table of Contents

1. [North Star & Guiding Principles](#1-north-star--guiding-principles)
2. [Current State Assessment](#2-current-state-assessment)
3. [Target Architecture](#3-target-architecture)
4. [Intelligence Domain Coverage](#4-intelligence-domain-coverage)
5. [Phase Roadmap](#5-phase-roadmap)
   - Phase 0 — Foundation Hardening
   - Phase 1 — Core Intelligence Modules
   - Phase 2 — AI & ML Integration
   - Phase 3 — Real-Time & Streaming Intelligence
   - Phase 4 — Advanced Tradecraft & Analytics
   - Phase 5 — Platform Maturity & Ecosystem
6. [Engineering Standards](#6-engineering-standards)
7. [System Design Principles](#7-system-design-principles)
8. [Security & OPSEC Standards](#8-security--opsec-standards)
9. [Data Pipeline Architecture](#9-data-pipeline-architecture)
10. [API & Integration Layer](#10-api--integration-layer)
11. [README.md & AGENTS.md Living Document Strategy](#11-readmemd--agentsmd-living-document-strategy)
12. [Contribution & Development Workflow](#12-contribution--development-workflow)
13. [Success Metrics & KPIs](#13-success-metrics--kpis)
14. [Risk Register](#14-risk-register)

---

## 1. North Star & Guiding Principles

### Vision Statement
> **1ai-osint** is the open-source intelligence platform that analysts, researchers, red teams, journalists, and national-security-adjacent professionals reach for first — because it is faster, deeper, and more actionable than any alternative.

### Core Principles

| # | Principle | Meaning |
|---|-----------|---------|
| 1 | **Data Supremacy** | Every module maximizes signal, minimizes noise |
| 2 | **Speed at Scale** | Sub-second queries on billion-row datasets |
| 3 | **Modular by Default** | Every feature is independently deployable |
| 4 | **Zero Trust Architecture** | Never assume input, network, or user is safe |
| 5 | **Ethical by Design** | Legal, consent-aware, auditable by default |
| 6 | **Docs are Code** | README.md and AGENTS.md are always in sync with `main` |
| 7 | **Automate Everything** | CI/CD, testing, linting, docs generation are never optional |
| 8 | **Always Production-Grade** | No toy code, no "we'll clean it later" debt |

---

## 2. Current State Assessment

### Repo: `oyi77/1ai-osint`

**Assumed Baseline** (to be validated on first audit):

| Area | Status | Priority to Fix |
|------|--------|----------------|
| Project structure | Flat or minimal | CRITICAL |
| Test coverage | Unknown / likely low | CRITICAL |
| CI/CD pipeline | Absent or minimal | CRITICAL |
| Documentation | Sparse | HIGH |
| Modular architecture | Incomplete | HIGH |
| Data source integrations | Limited | HIGH |
| AI/ML enrichment | None or prototype | MEDIUM |
| Auth & OPSEC controls | Unknown | CRITICAL |
| Performance benchmarks | None | MEDIUM |

### Immediate Audit Checklist (Sprint 0)

- [x] `tree -L 3` — map full directory structure
- [x] Identify all existing modules and their responsibility boundaries
- [x] Inventory all external API calls and data sources currently used
- [x] Check for hardcoded secrets, tokens, API keys (rotate immediately if found)
- [x] Run static analysis: `bandit`, `ruff`, `mypy` (Python) or equivalent
- [x] Check `requirements.txt` / `pyproject.toml` for pinned versions
- [x] Identify any broken or stale code paths

---

## 3. Target Architecture

### High-Level System Diagram

```
┌───────────────────────────────────────────────────────────┐
│                    1ai-osint Platform                      │
│                                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│  │   CLI Tool   │  │  REST API   │  │   Web UI (Opt)  │   │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘   │
│         └────────────────┼──────────────────┘            │
│                          ▼                                │
│              ┌───────────────────────┐                    │
│              │  Orchestration Layer  │                    │
│              │  (Task Queue + DAG)   │                    │
│              └───────────┬───────────┘                    │
│                          │                                │
│     ┌────────────────────┼────────────────────┐          │
│     ▼                    ▼                    ▼           │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │  SIGINT  │    │  SOCMINT     │    │  GEOINT      │    │
│  │  Module  │    │  Module      │    │  Module      │    │
│  └──────────┘    └──────────────┘    └──────────────┘    │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │  HUMINT  │    │  CYBINT      │    │  FININT      │    │
│  │  Module  │    │  Module      │    │  Module      │    │
│  └──────────┘    └──────────────┘    └──────────────┘    │
│                          │                                │
│              ┌───────────▼───────────┐                    │
│              │    AI/ML Enrichment   │                    │
│              │  (Entity, Sentiment,  │                    │
│              │   Graph, Prediction)  │                    │
│              └───────────┬───────────┘                    │
│                          │                                │
│              ┌───────────▼───────────┐                    │
│              │    Storage Layer       │                    │
│              │  (Graph DB + Vector DB │                    │
│              │   + Time-Series + S3)  │                    │
│              └───────────────────────┘                    │
└───────────────────────────────────────────────────────────┘
```

### Recommended Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Core Language** | Python 3.12+ | Ecosystem dominance in OSINT/ML |
| **Async Runtime** | `asyncio` + `aiohttp` | High-concurrency scraping |
| **Task Queue** | Celery + Redis | Distributed job orchestration |
| **API Server** | FastAPI | Async, self-documenting, fast |
| **Graph DB** | Neo4j or ArangoDB | Entity relationship maps |
| **Vector DB** | Qdrant or Weaviate | Semantic search on intelligence data |
| **Time-Series** | TimescaleDB or InfluxDB | Tracking activity over time |
| **Object Storage** | MinIO (self-hosted S3) | Media, documents, evidence artifacts |
| **Search Index** | Elasticsearch | Full-text search across all intel |
| **LLM Enrichment** | LiteLLM / OmniRoute | Multi-provider AI enrichment |
| **CLI** | Typer + Rich | Beautiful, powerful terminal UI |
| **Containerization** | Docker + Docker Compose | Zero-friction deployment |
| **Orchestration** | Kubernetes (optional) | Scale for large deployments |
| **CI/CD** | GitHub Actions | Integrated, free for OSS |
| **Secret Management** | `python-dotenv` + Vault | Never hardcode credentials |

---

## 4. Intelligence Domain Coverage

### Priority Matrix

| Domain | Code | Description | Priority |
|--------|------|-------------|----------|
| Social Media Intelligence | SOCMINT | Twitter/X, Instagram, LinkedIn, TikTok, Telegram, Discord profiling | P0 |
| Cyber Intelligence | CYBINT | IP/domain recon, port scan, SSL analysis, threat feeds | P0 |
| Signal Intelligence | SIGINT | Phone OSINT, email tracing, breach lookup | P0 |
| Geospatial Intelligence | GEOINT | IP geolocation, satellite imagery analysis, address resolution | P1 |
| Financial Intelligence | FININT | Blockchain tracing, wallet profiling, company financials | P1 |
| Dark Web Intelligence | DARKINT | Tor indexing, leak monitoring, paste site scraping | P1 |
| Human Intelligence Aggregation | HUMINT | Person profiling, relationship mapping, identity correlation | P1 |
| Document Intelligence | DOCINT | Metadata extraction, EXIF analysis, document fingerprinting | P2 |
| Network Intelligence | NETINT | BGP route analysis, autonomous system lookup, CDN detection | P2 |
| Satellite & Imagery | IMINT | Reverse image search, facial recognition pipeline, image geolocation | P2 |

---

## 5. Phase Roadmap

---

### PHASE 0 — Foundation Hardening
**Timeline:** 2 weeks
**Goal:** Make the codebase production-safe, maintainable, and CI-ready.

#### Tasks

- [x] **P0.1** — Restructure repo to monorepo layout:
  ```
  1ai-osint/
  ├── src/
  │   └── osint/
  │       ├── modules/
  │       ├── core/
  │       ├── api/
  │       └── cli/
  ├── tests/
  ├── docs/
  ├── scripts/
  ├── docker/
  ├── .github/workflows/
  ├── README.md
  ├── AGENTS.md
  ├── CHANGELOG.md
  └── pyproject.toml
  ```
- [x] **P0.2** — Setup `pyproject.toml` with proper deps, dev deps, and build config
- [x] **P0.3** — Configure `ruff` (linter), `mypy` (type checking), `black` (formatter)
- [x] **P0.4** — Write base `Makefile`: `make install`, `make test`, `make lint`, `make run`
- [x] **P0.5** — Setup GitHub Actions:
  - `ci.yml` — lint + test on every PR
  - `release.yml` — publish on tag push
  - `docs-sync.yml` — auto-update README.md version badge + changelog
- [x] **P0.6** — Create `docker-compose.yml` for full local stack (Redis, Neo4j, ES, etc.)
- [x] **P0.7** — Setup `.env.example` with all required env vars documented
- [x] **P0.8** — Write initial `AGENTS.md` with agent contract format
- [x] **P0.9** — Write initial `README.md` with badges, quickstart, and architecture section
- [x] **P0.10** — Pre-commit hooks: `pre-commit` with secret scanning, linting

**Definition of Done:** CI is green, `docker compose up` starts everything, `make test` runs without error.

---

### PHASE 1 — Core Intelligence Modules
**Timeline:** 4–6 weeks
**Goal:** Deliver the 3 highest-value OSINT domains with production-grade quality.

#### 1.1 SOCMINT Engine

- [x] Username enumeration across 100+ platforms (inspired by Sherlock, but with async speed)
- [x] Twitter/X profile deep scraper: followers, following, tweet history, network graph
- [x] Instagram OSINT: profile, tagged posts, location extraction from media
- [x] Telegram group membership scraper and message archive
- [x] LinkedIn profile aggregator (respectful of ToS, via public data)
- [x] Discord server member profiling
- [x] Cross-platform identity correlation engine (same username / avatar hash matching)
- [x] Social graph builder → exports to Neo4j

#### 1.2 CYBINT Engine

- [x] Subdomain enumeration (passive + active): `crt.sh`, `amass`, `subfinder` integration
- [x] IP reputation lookup: AbuseIPDB, GreyNoise, Shodan, Censys
- [x] Port scan orchestrator with `nmap` / `masscan` backend
- [x] SSL/TLS cert history and transparency log parser
- [x] WHOIS history enrichment
- [x] ASN + BGP route analysis
- [x] Technology fingerprinting: Wappalyzer-style stack detection
- [x] Web archive timeline: Wayback Machine delta analysis

#### 1.3 SIGINT Engine

- [x] Phone number OSINT: carrier lookup, country of origin, reputation score, breach check
- [x] Email OSINT: validity, breach database lookup (HIBP), associated accounts
- [x] Breach data aggregator interface (HaveIBeenPwned, Dehashed API adapter)
- [x] Email header forensics parser
- [x] IMSI / IMEI lookup (publicly available data only)

**Output formats for all modules:**
- JSON (machine-readable)
- Markdown report
- Neo4j graph import
- CSV export

**Definition of Done:** Each module has >80% test coverage, CLI entry point, and integration test.

---

### PHASE 2 — AI & ML Integration
**Timeline:** 4–6 weeks
**Goal:** Transform raw data into structured, enriched intelligence using AI.

#### 2.1 Entity Extraction Pipeline

- [x] Named Entity Recognition (NER) on all scraped text: persons, organizations, locations, events
- [x] Entity resolution: deduplicate same entity across sources
- [x] Entity timeline reconstruction
- [x] Relationship extraction: "Person X works at Org Y", "Domain A resolves to IP B"

#### 2.2 LLM-Powered Analysis

- [x] Intelligence summary generation per target (1–2 paragraph analyst brief)
- [x] Threat assessment scoring: risk level, activity indicators
- [x] Behavioral profiling: language patterns, activity timing, sentiment trends
- [x] Anomaly detection: flag unusual behavior changes in monitored targets
- [x] Multi-source synthesis: correlate signals across SOCMINT + CYBINT + SIGINT

**LLM Backend:** Route via LiteLLM / OmniRoute — supports GPT-4o, Claude, Gemini, local Ollama.

#### 2.3 Image Intelligence

- [x] EXIF metadata extraction and GPS coordinate plotting
- [x] Reverse image search automation (Google Lens, Yandex, TinEye via API)
- [x] Image geolocation pipeline (GeoSpy-style shadow/landmark analysis)
- [x] Face clustering for multi-source photo correlation (offline model only — no cloud)

#### 2.4 Graph Analytics

- [x] Betweenness centrality: identify key connectors in social networks
- [x] Community detection: cluster analysis on relationship graphs
- [x] Shortest path analysis: degrees of separation between targets
- [x] Temporal graph evolution: how networks change over time

---

### PHASE 3 — Real-Time & Streaming Intelligence
**Timeline:** 3–4 weeks
**Goal:** Monitor targets continuously, not just on-demand.

#### 3.1 Monitoring Engine

- [x] Target watchlist: define entities (person, domain, IP, username) to continuously monitor
- [x] Change detection: alert when new content, new connections, or new breaches appear
- [x] Streaming ingest from Twitter/X Firehose (where API permits), RSS, and Telegram channels
- [x] Scheduled job engine: cron-based re-scan of all watchlist targets

#### 3.2 Alerting & Notification

- [x] Alert rules engine: "if new breach for email X, notify"
- [x] Delivery channels: Telegram bot, Slack webhook, email, Discord webhook
- [x] Alert severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- [x] Alert deduplication: prevent alert storm on high-frequency events

#### 3.3 Timeline Intelligence

- [x] Event timeline builder for any target: all observed events in chronological order
- [x] Correlation timeline: detect when multiple unrelated signals converge on same entity
- [x] Time-series anomaly detection on target activity patterns

---

### PHASE 4 — Advanced Tradecraft & Analytics
**Timeline:** 4–6 weeks
**Goal:** Add capabilities that put this on par with nation-state tooling.

#### 4.1 FININT — Financial Intelligence

- [x] Blockchain address profiler: Bitcoin, Ethereum, Solana, TRON
- [x] On-chain transaction graph: follow the money across hops
- [x] Wallet clustering: identify wallets likely controlled by same entity
- [x] DeFi protocol exposure analysis
- [x] CEX deposit/withdrawal pattern detection (where public data available)
- [x] Sanctions list cross-reference: OFAC, UN, EU

#### 4.2 DARKINT — Dark Web Intelligence

- [x] Tor crawler with circuit rotation and identity isolation
- [x] Paste site monitor: Pastebin, Ghostbin, Rentry, Telegram paste channels
- [x] Ransomware group leak site tracker
- [x] Dark web forum keyword monitoring
- [x] Credential leak alerting

#### 4.3 GEOINT — Geospatial Intelligence

- [x] IP geolocation with confidence intervals
- [x] Physical location inference from social media posts (check-ins, tagged photos, metadata)
- [x] Address resolution and property lookup integration
- [x] Travel pattern reconstruction from activity timestamps + location data
- [x] Satellite imagery integration (Sentinel Hub, Maxar where available)

#### 4.4 Network Analysis & Attribution

- [x] Infrastructure pivoting: from domain → IP → hosting → related domains
- [x] Malware infrastructure tracking: C2 server identification patterns
- [x] Passive DNS analysis: historical DNS record timeline
- [x] Certificate fingerprinting for infrastructure clustering
- [x] Shodan/Censys automated pivot chains

---

### PHASE 5 — Platform Maturity & Ecosystem
**Timeline:** Ongoing
**Goal:** Make 1ai-osint the default choice for the global OSINT community.

#### 5.1 Plugin/Extension System

- [x] Module plugin API: `PluginRegistry().discover()` scans `src.plugins` + `1ai_osint.plugins` entry points (verified `src/plugin/registry.py`); pyproject.toml now declares the `[project.entry-points."1ai_osint.plugins"]` group so third-party pip packages register automatically
- [x] Module registry: `osint install <package>` subcommand implemented — pip-installs a plugin package and re-discovers entry points (`src/cli/commands/config_commands.py::install`)
- [x] Hook system: `HookDispatcher` wired into the scan lifecycle — `deep_scan/engine.py` fires `on_scan_start` / `on_scan_end` / `on_error` (error-isolated); built-in `ExamplePlugin` in `src/plugins/` now fires on every deep scan

#### 5.2 Web UI (Optional but High Value)

- [x] Investigation dashboard: drag-and-drop target cards
- [x] Graph visualization: force-directed graph of relationships
- [x] Timeline view: all events per target on a zoomable timeline
- [x] Report builder: compose multi-source intelligence reports with one click
- [x] Collaborative investigations: multi-user, team-based case management

#### 5.3 Case Management

- [x] Investigation case: bundle all artifacts for a single target/operation
- [x] Evidence chain of custody: immutable audit trail for legal proceedings
- [x] Export to PDF intelligence report
- [x] MITRE ATT&CK and MITRE ATLAS tagging for findings

#### 5.4 Community & Ecosystem

- [x] Published module SDK with docs and examples
- [x] Benchmark suite: compare 1ai-osint vs other tools on speed/coverage
- [x] Monthly threat feed integration updates
- [x] Integration adapters: Maltego, Obsidian, Notion export

---

## 6. Engineering Standards

### Code Quality Gates (enforced by CI — no merge without passing)

| Gate | Tool | Threshold |
|------|------|-----------|
| Linting | `ruff` | Zero errors |
| Type checking | `mypy` (strict) | Zero errors |
| Formatting | `black` | Auto-applied |
| Test coverage | `pytest-cov` | ≥ 80% per module |
| Security scan | `bandit` | Zero HIGH/CRITICAL |
| Dependency audit | `pip-audit` | Zero known CVEs |
| Secrets scan | `detect-secrets` | Zero leaks |
| Docstring coverage | `pydocstyle` | ≥ 90% public API |

### Commit Convention (enforced by `commitlint`)

```
type(scope): short description

Types: feat | fix | docs | refactor | test | chore | perf | security
Scope: module name (socmint | cybint | sigint | core | api | cli | docs)

Examples:
feat(socmint): add telegram group member scraper
fix(cybint): fix SSL cert parsing for wildcard domains
docs(readme): update architecture diagram for phase 2
security(core): rotate API key handling to vault backend
```

### Branch Strategy

```
main          ← always deployable, protected
dev           ← integration branch
feature/*     ← individual feature work
fix/*         ← bug fixes
docs/*        ← documentation-only changes
release/*     ← release candidate prep
```

### PR Requirements

- [x] Linked to an issue or roadmap item
- [x] All CI gates green
- [x] At least 1 reviewer approved
- [x] `CHANGELOG.md` entry added
- [x] Relevant README.md / AGENTS.md sections updated

---

## 7. System Design Principles

### 1. Module Contract (every module MUST implement)

```python
from osint.core.base import BaseModule, IntelResult

class MyModule(BaseModule):
    name: str = "module-name"
    version: str = "1.0.0"
    description: str = "What this module does"

    async def run(self, target: str, options: dict) -> IntelResult:
        """Execute intelligence gathering."""
        ...

    async def validate_target(self, target: str) -> bool:
        """Validate input before running."""
        ...

    def to_graph(self, result: IntelResult) -> list[GraphNode]:
        """Export result as graph nodes/edges for Neo4j."""
        ...
```

### 2. Rate Limiting & Respectful Scraping

- Every external request MUST go through the `RateLimiter` middleware
- Per-domain configurable delays
- Exponential backoff on 429 responses
- User-agent rotation pool
- Proxy rotation support (optional)

### 3. Caching Strategy

| Data Type | Cache TTL | Backend |
|-----------|-----------|---------|
| WHOIS records | 24h | Redis |
| IP geolocation | 7d | Redis |
| Social profile snapshot | 6h | Redis |
| Breach lookup | 1h | Redis |
| Graph relationships | 30d | Neo4j |
| Raw scraped content | 24h | MinIO |

### 4. Error Handling

- All exceptions categorized: `SourceUnavailableError`, `RateLimitError`, `InvalidTargetError`, `AuthError`, `ParseError`
- Every module returns partial results on partial failure (never silent drop)
- Structured logging with `structlog` — JSON format in production
- Sentry integration for error tracking (optional, opt-in)

### 5. Observability

- OpenTelemetry traces for all module executions
- Prometheus metrics: module runtime, success/failure rate, data volume
- Grafana dashboard template included in `docker/`
- Health check endpoint: `GET /health` returns module status + data source availability

---

## 8. Security & OPSEC Standards

### Operator OPSEC (for users of the tool)

- [x] All requests routable through SOCKS5/HTTP proxy (Tor, commercial proxy)
- [x] Optional Tor circuit rotation for dark web modules
- [x] VPN-aware: detect and warn if running without VPN on sensitive modules
- [x] Identity isolation: separate browser profiles / request identities per investigation
- [x] Operational logging: all actions logged with timestamps for audit trail

### Tool Security (protecting the tool itself)

- [x] No secrets in code — ever. All credentials via env vars or vault
- [x] API keys encrypted at rest (if stored)
- [x] Input sanitization on all external data (no eval, no shell injection)
- [x] SSRF protection on URL-fetching modules
- [x] Rate limiting on API server to prevent abuse — implemented as per-source RPM ceilings in `src/core/tos_guard.py` plus a `RateLimiter` (30 req/min, burst 5) in `src/modules/deep_scan/deep_scraper.py`
- [x] JWT-based authentication for multi-user deployments
- [x] RBAC: investigator, analyst, admin roles

### Legal & Ethical Framework

- [x] Built-in ToS compliance checklist per data source
- [x] Consent mode: flag when targeting individuals vs organizations
- [x] Jurisdiction warning: alert if operation may violate local laws
- [x] Audit log export for legal proceedings (tamper-evident)
- [x] PII handling policy: no long-term storage of personal data beyond investigation scope
- [x] **Compliance layer (blueprint Phase 0)**: legal-basis registry (78 sources incl. govt open-data), central JSONL audit log at the adapter layer, consent gate for Pasal 4.2 categories, 30-day retention purge — see [compliance.md](compliance.md)
- [x] **MCP bridge (blueprint Phase 1 S3)**: `src/mcp_bridge/server.py` — FastMCP server exposing search / list_sources / source_compliance to any MCP client
- [x] **Thin agent loop (blueprint Phase 1 S4)**: `deep_scan/agent_loop.py` — rule-based planner + alternate-source fallback on rate-limit/error; 6.22x vs naive batch (`scripts/benchmark_agent_vs_batch.py`)
- [x] **Open-government adapters (blueprint Phase 2 S5)**: PANDI RDAP + data.go.id (Satu Data Indonesia) with `government_open_data` legal basis
- [x] **RBAC per user tier (blueprint Layer 3)**: `src/core/rbac.py` — AccessTier (readonly/analyst/admin), token→tier resolution (`WEB_AUTH_TOKENS="tier:token,..."`, legacy `WEB_AUTH_TOKEN` = admin), per-source `min_tier` gate enforced in `run_source_scan` + `run_free_intel_scan` + MCP `search(requester_tier=...)`; web auth middleware resolves tier into `scope["auth_tier"]` (`/api/auth/tier`)
- [x] **ToS guard per source (blueprint Layer 3)**: `src/core/tos_guard.py` — per-source `requests_per_minute` ceiling from the compliance registry (breach DBs capped at 10 rpm), enforced before every external query; over-limit calls are throttled and recorded as `outcome="throttled"` in the audit trail

---

## 9. Data Pipeline Architecture

### Ingest → Process → Enrich → Store → Query

```
[Raw Source]
     │
     ▼
[Collector] ─── rate limiter ─── proxy layer
     │
     ▼
[Raw Storage] ←─── MinIO (evidence preservation)
     │
     ▼
[Parser/Normalizer] ─── structured JSON schema
     │
     ▼
[AI Enricher] ─── NER, sentiment, entity resolution
     │
     ├──────────────────────────────────────┐
     ▼                                      ▼
[Graph DB: Neo4j]              [Search Index: Elasticsearch]
(relationships, pivots)        (full-text query across all data)
     │                                      │
     └──────────────┬───────────────────────┘
                    ▼
            [Query API / CLI]
                    │
                    ▼
            [Report Generator]
```

### Data Schema Standard

Every module output MUST conform to the `IntelResult` schema:

```json
{
  "module": "socmint.twitter",
  "version": "1.0.0",
  "target": "username123",
  "timestamp": "2026-06-03T10:00:00Z",
  "confidence": 0.92,
  "data": { ... },
  "entities": [
    { "type": "PERSON", "value": "John Doe", "confidence": 0.88 }
  ],
  "relationships": [
    { "from": "username123", "relation": "FOLLOWS", "to": "username456" }
  ],
  "sources": ["twitter.com/username123"],
  "metadata": {
    "duration_ms": 234,
    "requests_made": 3,
    "cache_hit": false
  }
}
```

---

## 10. API & Integration Layer

### REST API Design

```
POST   /api/v1/query              ← run a one-shot query
GET    /api/v1/results/{job_id}   ← poll async result
GET    /api/v1/targets            ← list watchlist targets
POST   /api/v1/targets            ← add target to watchlist
DELETE /api/v1/targets/{id}       ← remove from watchlist
GET    /api/v1/graph/{entity}     ← get graph data for entity
GET    /api/v1/reports/{id}       ← get generated report
POST   /api/v1/export             ← export data in given format
GET    /api/v1/health             ← system health check
```

### CLI Design

```bash
# One-shot queries
osint query person "John Doe" --modules socmint,sigint --output json
osint query domain "example.com" --modules cybint,netint --depth 3
osint query ip "1.2.3.4" --modules cybint,geoint

# Watchlist management
osint watch add --target "username123" --type person --modules socmint
osint watch list
osint watch remove --id abc123

# Report generation
osint report generate --target "example.com" --template analyst-brief
osint report export --id abc123 --format pdf

# Graph operations
osint graph show --entity "username123" --depth 2
osint graph export --format cypher  # for Neo4j import

# System management
osint status          # check all module + data source health
osint update sources  # update threat feeds and breach databases
```

---

## 11. README.md & AGENTS.md Living Document Strategy

### The Rule: Docs are merged with code. No exception.

Every PR that changes module behavior MUST include a corresponding docs update. CI will fail if:
- A new module is added without a README section
- A new CLI command is added without being documented in README
- A new agent capability is added without AGENTS.md update

### README.md Structure (always maintained)

```markdown
# 1ai-osint
[badges: CI, coverage, version, license, Docker]

## Quick Start
## Architecture
## Modules
## CLI Reference
## API Reference
## Deployment
## OPSEC Guide
## Contributing
## Changelog
## License
```

### AGENTS.md Structure (always maintained)

```markdown
# AGENTS.md

## Overview
## Agent Registry
## Module Contracts
## Tool Capabilities
## Integration Points
## Prompt Engineering Guide (for LLM-powered modules)
## Agent Changelog
```

### Auto-generation

- Module list in README auto-generated from `src/osint/modules/*/manifest.json`
- CLI reference auto-generated from `typer` docstrings via `typer utils docs`
- API reference auto-generated from FastAPI's `/openapi.json`
- CHANGELOG auto-generated from conventional commits via `git-cliff`

---

## 12. Contribution & Development Workflow

### Local Dev Setup

```bash
git clone https://github.com/oyi77/1ai-osint
cd 1ai-osint
make install          # installs deps + pre-commit hooks
cp .env.example .env  # fill in API keys
docker compose up -d  # start Redis, Neo4j, Elasticsearch
make run              # start API server
make test             # run test suite
```

### Creating a New Module

```bash
# Use the module scaffold generator
python scripts/new_module.py --name "mymodule" --domain "cybint" --description "..."
# → creates src/osint/modules/cybint/mymodule/ with base files
# → creates tests/modules/cybint/test_mymodule.py
# → adds entry to AGENTS.md module registry
```

### Release Process

```
dev → PR review → merge to main → tag vX.Y.Z → GitHub Action:
  1. Run full test suite
  2. Build Docker image
  3. Publish to Docker Hub
  4. Update CHANGELOG.md
  5. Publish GitHub Release with release notes
  6. (Optional) Publish to PyPI
```

---

## 13. Success Metrics & KPIs

### Technical KPIs

| Metric | Target |
|--------|--------|
| Module test coverage | ≥ 80% |
| CI pipeline duration | ≤ 5 minutes |
| API p99 latency (cached) | ≤ 100ms |
| API p99 latency (live query) | ≤ 5s |
| Time to run full profile on target | ≤ 60s |
| Data sources integrated | ≥ 50 in Phase 1 |
| Platforms covered (SOCMINT) | ≥ 100 in Phase 2 |
| Uptime (self-hosted) | ≥ 99.5% |

### Community KPIs (Phase 5)

| Metric | Target |
|--------|--------|
| GitHub Stars | 1,000+ |
| Contributors | 20+ |
| Community modules published | 10+ |
| Cited in security research | 5+ papers/articles |
| Docker Hub pulls | 10,000+ |

---

## 14. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| API rate limit changes by data sources | HIGH | HIGH | Abstract all sources behind adapter; add fallback sources |
| Legal/ToS disputes from aggressive scraping | MEDIUM | HIGH | Rate limiting, respect robots.txt, ToS compliance mode |
| Secret/API key leak in commits | MEDIUM | CRITICAL | Pre-commit secret scanning, rotate on detection |
| Module quality decay over time | MEDIUM | HIGH | Mandatory tests, CI enforcement, module health dashboard |
| Dark web module misuse | MEDIUM | HIGH | Ethical mode toggle, usage logging, clear ToS in README |
| LLM API cost explosion on enrichment | LOW | MEDIUM | Token budgets, caching, support for local Ollama backend |
| Data storage cost at scale | LOW | MEDIUM | TTL policies, tiered storage, configurable retention |
| Supply chain attack via dependencies | LOW | CRITICAL | `pip-audit` in CI, pinned deps, Dependabot enabled |

---

## Appendix: Changelog Update Protocol

After every significant change, update `CHANGELOG.md` using this format:

```markdown
## [vX.Y.Z] - YYYY-MM-DD

### Added
- New SOCMINT module: Telegram group scraper

### Changed
- CYBINT: port scan now uses masscan backend by default

### Fixed
- SIGINT: phone number parser failed on +62 prefix

### Security
- Rotated API key handling to environment variables
```

---

*This document is the single source of truth for 1ai-osint's development direction. It must be reviewed and updated at the start of every new phase. All contributors must read PLAN.md before opening a PR.*

**Last Updated:** 2026-07-28
**Owner:** @oyi77
**Status:** ACTIVE — Phase 2 (AI & ML Integration), Phase 0 (Foundation Hardening) ✅, Phase 1 (Core Intelligence Modules) ✅
