# Blueprint Gap Analysis

> Strategic analysis of the August 2026 BerkahKarya blueprint
> *"1ai-osint — Blueprint Menuju OSINT Engine Terbaik di Dunia"* against the
> actual codebase at commit `00b387e`. Every claim below is grounded in
> verified source code; nothing is inferred from memory.

## 1. Baseline

| Item | Value |
| --- | --- |
| Commit analyzed | `00b387e` (38 files, +2123/−695) |
| Test suite | 2215 collected → 2207 passed, 8 skipped |
| Coverage | 77% (18861 stmts / 4385 missed) |
| Type check | mypy: 291 files, 0 errors |
| Lint | `ruff check src/ tests/` — 0 errors |
| Docs build | `mkdocs build` OK |

The blueprint defines "best in the world" across 5 axes (breadth, correlation
& reasoning, visual/UX, automation/agentic, trust & compliance), proposes 3
moats (local ID/SEA data, agentic-first architecture, compliance-by-design),
a 5-layer reference architecture, and a 4-phase roadmap.

## 2. Material correction: Phase-1 sources already exist

The blueprint's Phase-1 source set (theHarvester, Sherlock/Maigret, HIBP,
Amass, Shodan, Holehe) is **already present as live adapters** — it must not
be rebuilt:

```
src/modules/sources/
├── theharvester_source.py  sherlock_source.py  maigret_source.py
├── hibp_source.py          amass_source.py     shodan_source.py
├── holehe_source.py        phoneinfoga_source.py  whatsmyname_source.py
└── + 57 more adapters (censys, intelx, dehashed, leakcheck, otx, github, ...)
```

- Uniform interface: `search_for_address(address) -> list[RawLeak]` via
  `src/modules/sources/base.py:BaseLeakSource`. Rate limiting and caching are
  not applied per adapter — they are enforced centrally at the orchestration
  layer: `src/core/tos_guard.py` caps each source's requests-per-minute before
  every external query (throttled queries are recorded with
  `outcome="throttled"` in the audit log), and `src/modules/deep_scan/deep_scraper.py`
  applies `RateLimiter` (`requests_per_minute=30, burst=5`) with result caching
  via `src/core/cache.py`.
- Already bridged into the engine: `src/modules/deep_scan/source_adapter.py:run_source_scan()`
  converts `RawLeak` → `ScanResult` (`module="source_{name}"`, per-source
  `confidence`).
- Commit `00b387e` deleted **15 dead providers** under
  `src/vendor/chiasmodon/providers/` — a parallel duplicate layer with zero
  imports (verified in audit `a062e06`). Verified current state:
  `src/modules/sources/chiasmodon_bridge.py` still maps 10 source names
  (`hibp`, `shodan`, `scylla`, `leakcheck`, `breachdirectory`, `snusbase`,
  `intelx`, `dehashed`, `pastebin`, `reddit_leak`) to modules that all still
  exist. The deleted `providers/shodan.py` is **not** the `shodan/__init__.py`
  the bridge references. No dangling references.

**Consequence:** the global half of the blueprint's Layer 1 (Data Sources) is
already implemented. The remaining value is in integration, compliance, and
the ID/SEA moat — not in re-implementing adapters.

## 3. Gap map: blueprint 5-layer architecture vs `00b387e`

| Layer | Status | Evidence / Gap |
| --- | --- | --- |
| **L5 — Output & Reporting** | ~80% | `report_engine/html_template.py`, `output/` (pdf, sarif, json, report_generator, zkit_formatter), `deep_scan/ai_briefing.py` + `briefing_builder.py` — narrative briefing already exists |
| **L4 — AI Reasoning & Correlation** | ~75% | `identity_tracking/`: `zkit_engine` (salted SHA-256), `correlation.py` (`CrossModuleCorrelator`, `ResolvedEntity`, `ingest_scan_results`, `correlate`, `_build_evidence`), `identity_graph`, `behavioral_fingerprint`, `counterintel`, `neo4j_export.py` |
| **L3 — Access Control & Compliance** | ~95% | Present: multi-tier bearer auth (`WEB_AUTH_TOKENS="tier:token,..."` + legacy `WEB_AUTH_TOKEN`=admin), **JWT sessions** (`src/web/auth.py` — `/api/auth/login` exchanges a static token for a signed HS256 JWT with `tier`+`exp` claims; middleware verifies both static and JWT bearers), **per-route tier enforcement** (`require_tier()` FastAPI dependency, e.g. `/api/search` = ANALYST), RBAC gate (`src/core/rbac.py` — AccessTier readonly/analyst/admin, per-source `min_tier` enforced in `run_source_scan`/`run_free_intel_scan`/MCP `search(requester_tier=...)`), node audit trail (`node/db.py:get_audit_trail`, `GET /api/audit`), ZKIT redaction audit, case audit. **New (Phase 0):** `src/core/compliance.py` — legal-basis registry (78 sources incl. govt open-data), JSONL audit log at adapter layer, consent gate, 30-day retention purge. **New (Layer 3):** `src/core/tos_guard.py` — per-source `requests_per_minute` ceiling enforced before every external query (throttled → `outcome="throttled"` audit). **Remaining:** refresh-token rotation, per-source rate tiers per tier level |
| **L2 — Source Adapter / Tool Layer** | 65% | Uniform adapters ✅. **MCP-native ✅** — `src/mcp_bridge/server.py` (FastMCP, Phase 1 S3) exposing search/list_sources/source_compliance; thin agent loop (`deep_scan/agent_loop.py`, Phase 1 S4) with rule-based planning + rate-limit fallback |
| **L1 — Data Sources** | 65% | Global: 66 adapters, deep in crypto/leak/identity niches, not 200+ module breadth (SpiderFoot reference). **Local ID/SEA: partial ✅** — PANDI RDAP (`pandi_whois_intel`), data.go.id Satu Data Indonesia (`data_go_id_intel`), PDDIKTI. OSS/NIB, AHU, operator prefix mapping remain deferred to legal review |

## 4. Position on the blueprint's 5 axes

- **Breadth** — medium: broad in niche (crypto/leak/identity), thin in general
  infra/recon.
- **Correlation & reasoning** — above average; this is the platform's actual
  strength and is currently under-documented as a selling point.
- **Visual/UX** — web dashboard templates + **graph visualization present**
  (vis-network on entity/timeline pages, JSON via
  `/api/timeline/{entity}.json`).
- **Automation/Agentic** — fixed pipeline (`deep_scan` engine) **+ thin agent
  loop** (`deep_scan/agent_loop.py`, S4): rule-based planner, parallel
  primary wave, alternate-source fallback on rate-limit/error — measured
  6.22x vs naive batch in `scripts/benchmark_agent_vs_batch.py`.
- **Trust & compliance** — auth + audit trail + **legal-basis registry and
  adapter-layer audit log** (Phase 0, `src/core/compliance.py`).

## 5. The 3 moats — readiness

1. **Local Data Superiority (ID/SEA)** — ~25%: open-government adapters live
   (PANDI RDAP, data.go.id, PDDIKTI) with `government_open_data` legal basis;
   OSS/NIB, AHU, operator prefix mapping stay research items until legal
   review.
2. **Agentic-First** — ~40%: MCP server (S3) + thin agent loop (S4) shipped;
   remaining headroom is deeper self-correction (multi-pass, confidence-
   driven re-planning) and MCP resource endpoints.
3. **Compliance-by-Design** — ~95%: legal-basis registry, adapter-layer audit
   log, consent gate, retention purge (Phase 0) + govt open-data tagging +
   **RBAC per tier** (`src/core/rbac.py`, `min_tier` gate) + **ToS guard per
   source** (`src/core/tos_guard.py`, per-source rpm ceiling, throttled audit
   outcome) + **JWT sessions + per-route tier enforcement**
   (`src/web/auth.py`, `/api/auth/login`, `require_tier()`). Remaining:
   refresh-token rotation, per-source rate tiers per tier level.

## 6. Phased execution plan

### Phase 0 — Compliance gate (priority 1; low risk, high ROI)

- **S1 — Legal-basis registry**: ✅ **EXECUTED — `src/core/compliance.py`**.
  `LegalBasis` enum (`government_open_data` / `legitimate_interest` /
  `consent` / `public_api_tos` / `undocumented`), `SourceCompliance`
  (with `legal_basis`, `retention_days`, `requires_consent`), 76 sources
  backfilled; unknown sources default to `undocumented` so gaps stay visible.
  Paid breach DBs (dehashed, intelx, leakcheck, snusbase, snylla) flagged
  `undocumented` + legal-review note per blueprint §3 ⛔.
- **S2 — Central audit log at the adapter layer**: ✅ **EXECUTED**.
  `run_source_scan()` now audits every query (source, target, legal_basis,
  timestamp, requester, outcome) to JSONL (`AUDIT_LOG_PATH`, default
  `.osint_audit.jsonl`); consent-flagged sources are blocked pre-query and
  the block is audited; `purge_expired_audit_entries()` enforces the 30-day
  retention default. Tests: valid query, rate-limited query, consent-flagged
  source, RBAC tier gate, ToS throttling — `tests/unit/test_compliance.py`
  + `tests/unit/test_rbac_tos.py`, all passing.

### Phase 1 — Agentic validation (priority 2)
- **S3 — Minimal MCP server**: ✅ **EXECUTED — `src/mcp_bridge/server.py`**
  (named `mcp_bridge` — not `mcp` — so it cannot shadow the official MCP SDK
  package). FastMCP server exposing `search(target, source_filter)` (wraps
  `run_source_scan()` + `correlate()`), `list_sources()` and
  `source_compliance()`. No re-implementation — delegates to the existing
  adapter + correlation engine. Tested via in-process memory-stream MCP
  client (initialize → list tools → call tools): 6 tests in
  `tests/unit/test_mcp_server.py`, all passing. Run standalone:
  `uv run python -m src.mcp_bridge.server` (stdio).
- **S4 — Thin agent loop in `deep_scan`**: ✅ **EXECUTED —
  `src/modules/deep_scan/agent_loop.py`**. 1 input → rule-based planner
  (`detect_target_type` → ordered plan per type: email/phone/username/domain/
  name/crypto) → parallel primary wave → fallback to alternates on
  rate-limit/error → structured `AgentScanReport`. Compliance gate: consent-
  required sources blocked pre-run (UU PDP). 17 tests in
  `tests/unit/test_agent_loop.py`, all passing.

### Phase 2 — Local moat (priority 3; needs scope approval per §4)
- **S5 — Open-government adapters**: ✅ **EXECUTED — `pandi_whois_intel.py`**
  (PANDI RDAP, RFC 7483, for .id domains — registrant, nameservers, dates)
  + `data_go_id_intel.py` (Satu Data Indonesia dataset search). Both
  registered in `_FREE_INTEL_DISPATCH`, tagged `government_open_data` in the
  compliance registry (strongest UU PDP basis), and wired into the agent
  loop plans (domain → pandi_whois; name → data_go_id). 12 tests in
  `tests/unit/test_government_intel.py`, all passing. OSS/NIB, AHU,
  marketplace scrapers remain deferred to legal review.
  - **Endpoint fix (commit `b13a27d`)**: the PANDI RDAP endpoint was
    missing the `/rdap/` path segment (IANA bootstrap: the `.id` base is
    `https://rdap.pandi.id/rdap/`), so every live lookup 404'd. Fixed +
    regression test. Live-verified: `pandi.id` → PANDI Registrar (created
    2013-04-14, expires 2027-04-14, 3 NS); `google.co.id` → PT Digital
    Registra Indonesia (created 2004-12-18, ns1-4.google.com).

### Phase 3+ — Partial (foundation approved; only legal-safe items)
- ✅ **Head-to-head benchmark** — `scripts/benchmark_agent_vs_batch.py`:
  deterministic, mocked comparison of S4 agent loop vs naive batch scan —
  measured **6.22x wall-clock speedup**, 13/19 unnecessary source calls
  avoided, rate-limit errors absorbed by fallback.
- ✅ **Graph visualization** — already present (verified, gap-analysis line
  was stale): vis-network frontend + `/api/timeline/{entity}.json` JSON
  graph endpoint (`src/web/routes/timeline.py:_build_graph_data`).
- ⏸ Full Neo4j store — remains deferred (YAGNI; JSON export via
  `_neo4j_helpers.py` suffices for now).
- ⛔ Paid breach DBs — remain deferred pending legal review (blueprint §3).

## 7. Constraints & caveats

- UU PDP (Law 27/2022, enforced Oct 2024) governs: per-source legal basis,
  Pasal 4.2 sensitive-category prohibition, audit trail, ToS checks,
  retention default (~30 days, Sherlockeye standard), and ethical rate-limit /
  attribution guards.
- Do not scaffold Neo4j or an MCP layer wholesale in a single turn — those
  belong to the approved phased plan.
- Blueprint §6 prompt is truncated mid-sentence in the source document; its
  intended directive is inferred from the visible text only.

## See also

- [Architecture](architecture.md)
- [Roadmap](roadmap.md)
- [Modules](modules.md)
- [References](references.md)
