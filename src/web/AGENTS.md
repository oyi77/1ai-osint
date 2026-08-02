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
| `main.py` | uvicorn entry point (binds `127.0.0.1:8080`, override via `WEB_HOST`) |
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
- `require_tier` fails closed (403) when `auth_tier` is missing (`auth.py:116`)

## Dependencies

### Internal
- `src/core/rbac.py` — `AccessTier`, `tiers_from_env`
- `src/web/routes/` — all five routers registered in `create_app`
- JWT via PyJWT, HMAC key from `JWT_SECRET`

## Findings
- [RESOLVED-High] Fail-open ADMIN + default `0.0.0.0` binding — `require_tier` now fails closed (403) when no `auth_tier` is present (`auth.py:116`), and the server binds `127.0.0.1` by default, overridable via `WEB_HOST` (`main.py:15`, `commands/config_commands.py:122`).
- [RESOLVED-Medium] Dashboard/report pages scan the filesystem per request — `_load_scan_history` / entity / report / timeline loaders glob all `*.json` under CWD and `~/.1ai-osint` on every render, keeping `full_data` in memory; now cached via shared loader `routes/_loader.py` (30s TTL, used by entities/dashboard/timeline/reports).
- [RESOLVED-Low] Health endpoint exposes local paths — `data_directories` removed from the health response (`routes/api.py:66-89`).

> Last updated: added frontmatter, added `auth.py` to key files, added fail-open/0.0.0.0, per-request filesystem scans and path-disclosure findings (commit 8fa2bbf)
> Last updated: fix pass — fail-closed auth (403, auth.py:116), 127.0.0.1 default bind, shared 30s cached JSON loader (routes/_loader.py), health no longer exposes data_directories
