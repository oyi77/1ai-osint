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
  `src/modules/sources/base.py:BaseLeakSource`, with `rate_limiter.py` and
  `cache.py` applied per repo convention.
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
| **L3 — Access Control & Compliance** | ~25% | Present: `WEB_AUTH_TOKEN` middleware, node audit trail (`node/db.py:get_audit_trail`, `GET /api/audit`), ZKIT redaction audit (`output/zkit_formatter.py:RedactionAuditEntry`), case audit in `investigations/`. **Absent:** legal-basis tagging per source, retention/purge policy, ToS guard per source, RBAC per tier |
| **L2 — Source Adapter / Tool Layer** | 50% | Uniform adapters ✅. **MCP-native ❌** — zero MCP code anywhere in `src/` (verified grep). This is the blueprint's strongest architectural mandate (§2, §1.2) |
| **L1 — Data Sources** | 60% | Global: 66 adapters, deep in crypto/leak/identity niches, not 200+ module breadth (SpiderFoot reference). **Local ID/SEA: 0%** — no BPS/data.go.id, PANDI WHOIS, OSS/NIB, AHU, operator prefix mapping |

## 4. Position on the blueprint's 5 axes

- **Breadth** — medium: broad in niche (crypto/leak/identity), thin in general
  infra/recon.
- **Correlation & reasoning** — above average; this is the platform's actual
  strength and is currently under-documented as a selling point.
- **Visual/UX** — web dashboard templates exist; **no graph visualization**
  (neo4j_export exists without a graph frontend).
- **Automation/Agentic** — fixed pipeline (`deep_scan` engine: module list +
  scan profiles + iterations), **not an agent loop** that self-corrects /
  pivots on rate-limit or empty results.
- **Trust & compliance** — auth + partial audit trail; no legal-basis /
  retention layer yet.

## 5. The 3 moats — readiness

1. **Local Data Superiority (ID/SEA)** — 0%: greenfield. Blueprint §4 requires
   a legal-basis review first; the safe starting points are open-government
   data (BPS / data.go.id) and PANDI WHOIS format parsing. OSS/NIB, AHU, and
   marketplace scraping stay research items until legal review.
2. **Agentic-First** — 0%: no MCP server, no agent loop. Largest and most
   expensive slice.
3. **Compliance-by-Design** — ~25%: audit trail + auth exist; legal-basis
   tagging, retention, and ToS guards do not. **Highest ROI per effort** —
   it closes the gap already flagged by the ecosystem audit ("tool licensing
   & access control") and is immediately marketable.

## 6. Phased execution plan

### Phase 0 — Compliance gate (priority 1; low risk, high ROI)
- **S1 — Legal-basis registry**: new `src/core/compliance.py` — pydantic
  `LegalBasis` enum (`government_open_data` / `legitimate_interest` /
  `consent` / `public_api_tos`), plus `legal_basis`, `retention_days`,
  `requires_consent` fields on each source. Backfill all 66 sources from
  their actual API contracts.
- **S2 — Central audit log at the adapter layer**: wrap
  `run_source_scan()` so every query records source, target, legal_basis,
  timestamp, requester. Tests: valid query, rate-limited query,
  consent-flagged source.

### Phase 1 — Agentic validation (priority 2)
- **S3 — Minimal MCP server**: `src/mcp/server.py` exposing `search(target,
  source_filter)` as a tool that wraps `run_source_scan()` + `correlate()` —
  no re-implementation. Test via in-process MCP client.
- **S4 — Thin agent loop in `deep_scan`**: 1 input → rule-based planner picks
  relevant adapters → fallback to alternates on rate-limit → structured
  `ScanResult` output.

### Phase 2 — Local moat (priority 3; needs scope approval per §4)
- **S5 — Open-government adapters**: BPS / data.go.id (strongest legal basis)
  + PANDI WHOIS parser. OSS/NIB, AHU, marketplace scrapers deferred to legal
  review.

### Phase 3+ — Deferred (YAGNI until the foundation is approved)
- Full Neo4j store, graph visualization frontend, head-to-head benchmarks,
  paid breach DBs (post legal review).

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
