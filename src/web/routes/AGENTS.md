---
scope: src/web/routes
depends_on: [src/web/app, src/web/auth, src/core]
status: complete
---

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# routes

## Purpose
Web dashboard route handlers — HTTP endpoints for the investigation UI plus the `/api` JSON endpoints (health, stats, search, JWT login).

## Key Files
| File | Routes | Description |
|------|--------|-------------|
| `api.py` | `POST /api/auth/login`, `GET /api/auth/tier`, `GET /api/health`, `GET /api/stats`, `GET /api/search` | JSON API: JWT login, tier, health, stats, search (ANALYST-gated) |
| `dashboard.py` | `GET /` | Dashboard with summary stats |
| `entities.py` | `GET /entities`, `GET /entities/{id}` | Entity browsing, detail + timeline |
| `reports.py` | `GET /reports`, `GET /reports/{id}` | Report listing and detail viewer |
| `timeline.py` | `GET /timeline`, `GET /timeline/{id}`, `GET /api/timeline/{id}.json` | Global/entity timelines + graph data |

## For AI Agents

### Working In This Directory
- Routers are registered in `src/web/app.py:create_app()` (`include_router`, `app.py:94-98`)
- HTML routes render Jinja2 templates from `src/web/templates/`
- Data layer: each module re-parses `*.json` scan files from CWD + `~/.1ai-osint` via shared cached loader (`_loader.py`, 30s TTL)
- `require_tier(AccessTier.ANALYST)` gates `/api/search`

## Dependencies

### Internal
- `src/web/app.py` — app factory that registers these routers
- `src/web/auth.py` — `require_tier`, `issue_token`, `jwt_enabled`
- `src/core/rbac.py` — `AccessTier`, `tiers_from_env`
- `src/web/templates/` — Jinja2 templates

## Findings
- [RESOLVED-Medium] Repeated full-filesystem JSON scans — `_load_all_entities`, `_load_reports`, `_load_all_events`, `_load_scan_history` independently glob and parse the same files per request with duplicated skip-pattern lists; now centralized in shared cached loader `_loader.py` (30s TTL, `_TTL_SECONDS = 30.0`).
- [RESOLVED-Low] `timeline.py:110` fallback event id — was built-in `hash(str(ev))` (salted per process, ids differed between renders); now a stable sha1 hash.

> Last updated: added frontmatter, added missing `api.py` (JWT login/stats/search) to file list, corrected descriptions (search lives in api.py, not entities.py), added shared-loader + unstable-hash findings (commit 8fa2bbf)
> Last updated: fix pass — shared 30s TTL cached JSON loader (_loader.py) for entity/report/timeline/dashboard, stable sha1 fallback event id (timeline.py:110)
