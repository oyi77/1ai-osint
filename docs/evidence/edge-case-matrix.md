# Edge-Case Matrix — GATE 6 Evidence

Date: 2026-08-01 · Commit under test: `HEAD` (pre-commit `433698d` + uncommitted GATE work)
Method: live uvicorn probes (`src.api.app:app`) + unit tests + source audit.

## 1. HTTP surface (live, Mode A — fail-open default)

| Case | Expected | Actual | Verdict |
|---|---|---|---|
| `GET /health` | 200 | 200 | PASS |
| `GET /` | 200 | 200 | PASS |
| `GET /ui` | 200 | 200 | PASS |
| `GET /v1/jobs` (unauthenticated) | 200 (fail-open default) | 200 | PASS |
| `GET /nonexistent` | 404 | 404 | PASS |
| `POST /v1/scan` malformed JSON `{bad` | FastAPI body validation | **422** (not 400 — FastAPI rejects at validation layer) | PASS (recorded empirically) |
| `POST /v1/scan` `{"target": ""}` | 422 (empty target) | 422 | PASS |

Evidence: `docs/evidence/curl/basic_matrix_statuses.txt`.

## 2. Inbound rate limiting (live, Mode A — `AI_OSINT_API_RPM=60 AI_OSINT_API_BURST=5`)

Gap found during GATE 6: the API accepted scan-creation POSTs with **no inbound rate gate** —
an unauthenticated caller could queue scans without bound. Fixed by adding
`RequestLimiter` (in-memory token bucket, `time.monotonic`) applied to **both**
`POST /v1/scan` and `POST /api/scan` before job creation.

| Case | Expected | Actual | Verdict |
|---|---|---|---|
| 25 rapid POSTs (burst=5, refill 1/s) | mix of 200 then 429 | 11×200, 14×429 | PASS |
| 429 response headers | `retry-after: 1` | `retry-after: 1` present | PASS |
| 429 body | JSON detail | `{"detail":"Rate limit exceeded. Retry after one second."}` | PASS |
| 12-way parallel burst | 429 once bucket exhausted | 429s observed | PASS |
| `GET` reads with tight limiter (1 rpm, burst 1) | unaffected | 200 | PASS (unit) |
| Bucket recovery after refill | 200 after wait | 200 | PASS (unit) |
| Keyed per client | isolated buckets | `request.client.host` key, `"unknown"` fallback | PASS (source) |

Evidence: `docs/evidence/curl/burst_statuses.txt`, `docs/evidence/curl/burst_429_sample.txt`,
`tests/unit/test_api_rate_limit.py` (5 tests).

## 3. Auth fail-closed (live, Mode B — `REQUIRE_AUTH_TOKENS=1 WEB_AUTH_TOKEN=testtoken`)

| Case | Expected | Actual | Verdict |
|---|---|---|---|
| `GET /health` no token | 200 (exempt) | 200 | PASS |
| `GET /v1/jobs` no token | 401 | 401 | PASS |
| `GET /v1/jobs` `Bearer testtoken` | 200 | 200 | PASS |
| `POST /v1/scan` no token | 401 | 401 | PASS |
| `POST /v1/scan` `Bearer testtoken` | 200 | 200 | PASS |

Evidence: `docs/evidence/curl/auth_fail_closed_statuses.txt`, `tests/unit/test_auth_fail_closed.py`.

Auth-exempt paths (API app): `/health`, `/`, `/ui`, `/static/*`; (web app): `/api/health`,
`/static`, `/api/auth/login`. Everything else requires a valid token when fail-closed is enabled.

## 4. Fail-open default and least privilege

Default configuration is fail-open (`REQUIRE_AUTH_TOKENS` unset) so the tool runs
unauthenticated out of the box — an explicit product choice (local research tool, not a
public SaaS). Mitigation: unauthenticated requests are assigned
`AccessTier.READONLY` (least privilege), which blocks ANALYST+ actions (e.g.
CVE/exploit context enrichment, high-sensitivity source access) via the RBAC layer
(`src/core/rbac.py`, `src/core/compliance.py`). Operators who expose the service
network-facing must set `REQUIRE_AUTH_TOKENS=1`; this is documented in
`docs/configuration.md`.

## 5. CORS

Explicit allow-list only — `AI_OSINT_CORS_ORIGINS` env or settings default; never `*`.
Preflight handled by middleware registered last (outermost). Verified in source:
`src/api/app.py` `_cors_origins()` + `CORSMiddleware(allow_origins=...)`.

## 6. Outbound rate limiting / caching

All external calls are gated by the outbound `RateLimiter` (`src/core/rate_limiter.py`)
with disk-persisted state in `.osint_rate_limit.json` (survives restarts), and redundant
fetches are served from `src/core/cache.py` (`.osint_cache/`). Both are enforced at the
module level per repo conventions.

## 7. Known residual limitations (honest)

1. **In-memory job store is unbounded.** `_JOBS` is a module-level dict; only the
   *persisted* snapshot is capped (`_MAX_PERSISTED_JOBS = 100` to `state/jobs/jobs.json`).
   A long-running process with heavy scan volume grows memory. Residual — would need an
   LRU cap or a jobs table; out of scope for this pass.
2. **No per-token authz for web UI.** Web login (`/api/auth/login`) grants a session; the
   API bearer-token path is separate. Tier enforcement is per-request via scope, not per-session.
3. **Fail-open default** (see §4) — safe only for local/single-user use; network exposure
   requires explicit auth configuration.
4. **Live-source freshness not certifiable offline.** Module outputs depend on third-party
   sources (breach APIs, social platforms) whose liveness/coverage cannot be proven in an
   offline environment. Unit/benchmark evidence covers logic, not source availability.

## 8. Other hardening verified in this GATE pass

- **Phone normalization** (`src/utils/phone_normalize.py`) — E.164 normalization + carrier
  fallback for Indonesian numbers in `phone_finder` (`src/modules/phone_finder/lookup.py`);
  covered by `tests/unit/test_phone_normalize.py`, `tests/unit/test_phone_finder.py`.
- **Severity model** — fixed four-level severity (info/low/medium/high + critical where
  applicable) reweighted consistently across findings; detection benchmark
  (`tests/benchmarks/benchmark_detection.py`) asserts per-level distribution.
- **Noise audit** — `console.log`/stray `print()` sweep of `src/`: only intentional
  channels remain (CLI Rich console, `ConsoleAlerter` delivery, vendored lib, example plugin).
  No TODO/FIXME markers in `src/` (only false-positive `HACKTIVIST` matches).

## 9. Test evidence

- `tests/unit/test_api_rate_limit.py` — 5 new tests (rate limit, react endpoint, reads
  unaffected, recovery, reset).
- `tests/unit/test_auth_fail_closed.py` — fail-closed matrix.
- `tests/unit/test_api_app.py` — API behavior incl. requester-tier threading.
- Full suite: see `docs/evidence/MASTER_RECEIPT.md` (task J re-runs the suite; do not
  trust counts in this file over the live receipt).
