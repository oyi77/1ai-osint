---
scope: src/api
depends_on: [src/core, src/modules, src/web/app]
status: complete
---

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# api

## Purpose
FastAPI-based REST API layer — serves the legacy `/v1` JSON API and the ZKIT React dashboard `/api` endpoints, backed by one in-memory job store (`_JOBS`) persisted to `<project_root>/state/jobs/jobs.json`.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | FastAPI app, job runner (`_run_job`), CORS + optional bearer-token auth middleware, SSRF guard on scan targets |
| `__init__.py` | Package initializer |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `templates/` | Jinja2 HTML templates (served at `/` and `/ui`) |

## Endpoints
- `GET /health` — liveness probe
- `GET /v1/jobs`, `POST /v1/scan`, `GET /v1/scan/{job_id}` — legacy JSON API
- `POST /api/scan`, `GET /api/scan/{job_id}` — ZKIT React dashboard API
- `GET /` and `GET /ui` — dashboard HTML

## For AI Agents

### Working In This Directory
- Job models: `ScanRequest`, `ScanResponse`, `ReactScanRequest`, `ReactJobResponse` (`app.py`)
- Async only where needed — scan creation/status are `async`; listing/health are sync
- Rate limiting: `RequestLimiter` (`_rate_limit_or_429`) on scan-creation endpoints only, per-client in-memory
- SSRF guard: `validate_scan_target` (`src.core.ssrf_guard`) rejects private/internal targets
- Optional auth reuses `src.web.app.AuthMiddleware` via `_ApiAuthMiddleware`; default fail-open = READONLY tier, `REQUIRE_AUTH_TOKENS=1` fails closed
- CORS origins explicit (never `*`) so `allow_credentials=True` stays valid
- Background tasks tracked in `_TASKS` so they are never GC'd mid-run

## Dependencies

### Internal
- `src/core/` — `settings`, `rate_limiter`, `rbac`, `ssrf_guard`
- `src/modules/deep_scan/` — `engine`, `exports`, `report_generator`, `scan_profiles`
- `src/investigations/case_manager.py` — `CaseManager.save_run` (only when `case_id` set)
- `src/web/app.py` — base `AuthMiddleware` reused for bearer-token auth

## Findings
- [Medium] Job store grows unbounded — `_MAX_PERSISTED_JOBS = 100` only caps at load time (`_load_jobs`, `app.py:127`); `_create_job` (`app.py:218`) inserts without eviction and `_save_jobs` rewrites the whole file on every update → memory + I/O growth in long-running processes. Suggest a cap at insert time.
- [Medium] PDF always exported — `_run_job` calls `export_report(intel, fmt="pdf")` on every scan (`app.py:305`) but the bytes are only used when `case_id` is set (`app.py:324`) → wasted work on the common path.
- [Medium] `GET /v1/scan/{job_id}` / `GET /api/scan/{job_id}` (`app.py:267`, `app.py:363`) return the full job dict incl. `intel`/`html`/`error` (raw exception text, `app.py:331`), with no rate limit and only 48-bit job ids (`uuid4().hex[:12]`, `app.py:260`) — with auth off (default) any network caller can poll and read raw exception messages.
- [Low] SSRF target validation duplicated — `_clean_target` (`app.py:223`) vs inline re-check in `start_scan_react` (`app.py:349`); keep one helper.

> Last updated: added frontmatter, documented /api (React) surface + auth/rate-limit/SSRF details, added job-store/PDF/GET-enumeration findings (commit 8fa2bbf)
