---
scope: src/web
depends_on: [src/core, src/web/routes]
status: complete
---

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# web

## Purpose
Web dashboard — FastAPI app factory with routes, templates, static assets, and bearer-token + JWT auth (RBAC Layer 3).

## Key Files
| File | Description |
|------|-------------|
| `app.py` | `create_app()` factory, `AuthMiddleware` (bearer tokens + JWT fallback, resolved tier → `scope["auth_tier"]`) |
| `auth.py` | JWT issue/verify (`issue_token`, `verify_token`, `jwt_enabled`), `require_tier` dependency |
| `main.py` | uvicorn entry point (binds `0.0.0.0:8080`) |
| `__init__.py` | Package initializer |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `routes/` | Route handlers — dashboard, entities, reports, timeline, api (see `routes/AGENTS.md`) |
| `static/` | Static assets (CSS, JS, images) |
| `templates/` | Jinja2 HTML templates |

## For AI Agents

### Working In This Directory
- `create_app()` imports routers lazily to avoid circular imports; static dir mounted if present
- Auth disabled by default (fail-open); enabled when `WEB_AUTH_TOKEN` / `WEB_AUTH_TOKENS` set or `REQUIRE_AUTH_TOKENS=1`
- `require_tier` treats a missing `auth_tier` as ADMIN — no middleware = trusted local (see finding)

## Dependencies

### Internal
- `src/core/rbac.py` — `AccessTier`, `tiers_from_env`
- `src/web/routes/` — all five routers registered in `create_app`
- JWT via PyJWT, HMAC key from `JWT_SECRET`

## Findings
- [High] Fail-open ADMIN + default `0.0.0.0` binding — `require_tier` maps "auth middleware not installed" to `AccessTier.ADMIN` (`auth.py:116`), and the server binds all interfaces by default (`main.py:13`, `commands/config_commands.py:122`). With no tokens configured (the default), any network client reaches ADMIN-tier routes unauthenticated. Mitigation: bind 127.0.0.1 by default or fail closed.
- [Medium] Dashboard/report pages scan the filesystem per request — `_load_scan_history` / entity / report / timeline loaders glob all `*.json` under CWD and `~/.1ai-osint` on every render (`routes/dashboard.py:18`, `routes/entities.py:17`, `routes/reports.py:17`, `routes/timeline.py:17`), keeping `full_data` in memory (`routes/reports.py:69`) — no caching; slow with many/large scan files.
- [Low] Health endpoint exposes local paths (`routes/api.py:95-97`) — `data_directories` reveals CWD and home dir on an unauthenticated endpoint.

> Last updated: added frontmatter, added `auth.py` to key files, added fail-open/0.0.0.0, per-request filesystem scans and path-disclosure findings (commit 8fa2bbf)
