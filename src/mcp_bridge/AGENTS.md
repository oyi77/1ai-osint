---
scope: src/mcp_bridge
depends_on: [src/core/compliance, src/core/rbac, src/modules/deep_scan, src/modules/identity_tracking, src/modules/sources, src/core/models]
status: active
---
<!-- Parent: ../AGENTS.md -->

# AGENTS.md — src/mcp_bridge

## Tujuan Folder Ini
Expose 1ai-osint's deep-scan + ZKIT correlation pipeline as an MCP server (`FastMCP("1ai-osint")`, `server.py:46`) so any MCP-capable client can run breach/leak lookups without re-implementing adapters. Runs over stdio: `uv run python -m src.mcp_bridge.server` (`main()` at `server.py:270-273`). Package is named `mcp_bridge` (not `mcp`) so it cannot shadow the official `mcp` SDK imported in `server.py`.

## Ekspor / Interface Utama
- `server` (`server.py:46`) — FastMCP instance; tools, resources, and prompts registered on it:
  - Tool `search(target, source_filter=None, requester_tier="admin")` (`server.py:138-164`) — runs source adapters + correlation
  - Tool `list_sources()` (`server.py:184-187`) — sources with compliance metadata
  - Tool `source_compliance(source)` (`server.py:190-209`) — per-source legal basis/retention/consent
  - Resource `osint://sources` (`sources_resource()`, `server.py:215-218`) — JSON catalog
  - Prompt `investigate(target, source_filter=None)` (`server.py:224-264`) — guided investigation plan
- Helpers: `_run_sources` (`server.py:55-89`), `_correlate_results` (`server.py:92-135`), `_source_catalog` (`server.py:167-181`)
- `SOURCE_MODULES = {"dehashed","leakcheck","snylla","snusbase","hibp","intelx"}` (`server.py:44`) — manual mirror of `src/modules/deep_scan/_module_config.py:SOURCE_MODULES` (line 127)

## Dependensi Internal
- `get_compliance` — `src/core/compliance.py:253`
- `AccessTier` (class) + `from_str` — `src/core/rbac.py:28,36`
- `run_source_scan` — `src/modules/deep_scan/source_adapter.py:74`; gates inside: consent (`is_consent_required`, :106), RBAC (`source_allows_tier`, :122), ToS (`tos_allows`, :140)
- `CrossModuleCorrelator` + `ingest_scan_results` + `correlate` — `src/modules/identity_tracking/correlation.py:59,110,238`
- `discover_sources` — `src/modules/sources/__init__.py:18`
- `ScanResult` — `src/core/models.py:68` (lazy import at `server.py:104`)
- Tests: `tests/unit/test_mcp_server.py`

## Issue Spesifik
- **[High]** Default `requester_tier="admin"` (`server.py:142`) — a client that omits the parameter always gets the highest tier, so the RBAC gate at `source_adapter.py:122` never blocks: `search` (`server.py:142`) → `_run_sources` (`server.py:79-85`) → `run_source_scan` (`source_adapter.py:122`)
- **[Medium]** `investigation_id=f"mcp-{target[:32]}"` (`server.py:108`) — deterministic per target, not per run; repeated scans of the same target share one investigation id
- **[Medium]** Failed sources are recorded as `{"error": ...}` (`server.py:74-88`) then silently skipped in correlation at debug level (`server.py:112-117`) — the caller sees no error in the response
- **[Low]** `SOURCE_MODULES` (`server.py:43-44`) is a hand-maintained duplicate that can drift from `_module_config.py:SOURCE_MODULES`

## Rekomendasi Perbaikan Scoped
- **(High)** Change the tool default to fail closed — `requester_tier: str = "admin"` → `"readonly"` at `server.py:142`, so callers must explicitly request a higher tier:
  - Before: `requester_tier: str = "admin"` — omitted param bypasses all RBAC gates
  - After: `requester_tier: str = "readonly"` — omitted param is gated, explicit opt-in required for higher tiers
- **(Medium)** Include a run-specific salt in `investigation_id` (e.g. `mcp-{uuid4().hex[:8]}-{target[:24]}`) at `server.py:108`
- **(Medium)** Surface per-source errors in the tool response instead of skipping at debug level (`server.py:112-117`)
- **(Low)** Derive `SOURCE_MODULES` from `_module_config.py` instead of duplicating (`server.py:43-44`)

> Last updated: created — documented MCP surface (tools/resources/prompts), verified internal dependencies, and flagged fail-open RBAC default as High (commit 8fa2bbf)
