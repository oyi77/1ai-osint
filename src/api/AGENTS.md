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
- Rate limiting: `RequestLimiter` (`_rate_limit_or_429`) on scan-creation and job-status endpoints, per-client in-memory
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
- [RESOLVED-Medium] Job store grows unbounded — `_MAX_PERSISTED_JOBS = 100` only caps at load time (`_load_jobs`, `app.py:127`); `_create_job` now evicts the oldest persisted job past the cap at insert time (`app.py:219-225`).
- [RESOLVED-Medium] PDF always exported — `_run_job` called `export_report(intel, fmt="pdf")` on every scan but the bytes were only used when `case_id` was set; the export now runs inside `if req.case_id:` (`app.py:348-349`).
- [RESOLVED-Medium] `GET /v1/scan/{job_id}` / `GET /api/scan/{job_id}` — responses now pass through `_job_public()` (strips `intel`/`html`/`error`, `app.py:260-262`), job-status endpoints are rate limited (`_rate_limit_or_429`, `app.py:301`/`app.py:394`), and job ids are 128-bit (`job-{uuid4().hex}`, `app.py:292`/`app.py:385`).
- [RESOLVED-Low] SSRF target validation duplicated — `_clean_target` (`app.py:223`) vs inline re-check in `start_scan_react`; both paths now share `_clean_target_str` (`app.py:230`).

> Last updated: added frontmatter, documented /api (React) surface + auth/rate-limit/SSRF details, added job-store/PDF/GET-enumeration findings (commit 8fa2bbf)
> Last updated: fix pass — job-store eviction at insert (app.py:219-225), PDF export inside case_id branch (app.py:348-349), _job_public + rate-limited status endpoints + 128-bit job ids (app.py:260-262, 292, 301, 385, 394), SSRF dedup via _clean_target_str (app.py:230)
