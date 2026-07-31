# Web UI

1ai-osint ships a FastAPI web dashboard for browsing investigations and
results. Start it from the CLI:

```bash
uv run 1ai-osint web --host 0.0.0.0 --port 8080
```

This launches the application from `src/web/main.py`
(`app = create_app()` from `src/web/app.py`) under uvicorn.

## Routes

The application registers five routers (`src/web/app.py`):

| Route | Description |
| --- | --- |
| `/` | Dashboard overview (HTML). |
| `/entities` | Entity browser; `/entities/{entity_id}` shows one entity. |
| `/reports` | Report viewer; `/reports/{report_id}` shows one report. |
| `/timeline` | Timeline visualization. |
| `/api/*` | JSON API (`/api/health`, `/api/stats`, `/api/search?q=…`, `/api/timeline/{entity_id}.json`). |

Static assets are served from `src/web/static` under `/static`.

## Authentication

The web UI supports **optional bearer-token authentication** via the
`WEB_AUTH_TOKEN` environment variable (see the `=== Web UI ===` section of
`.env.example`).

Behavior (`src/web/app.py` — `AuthMiddleware`):

- **When `WEB_AUTH_TOKEN` is empty/unset** — the web UI runs
  **unauthenticated** (local development default).
- **When `WEB_AUTH_TOKEN` is set** — every HTTP request is rejected with
  `401 Unauthorized` unless it carries an `Authorization` header:

  ```text
  Authorization: Bearer <WEB_AUTH_TOKEN>
  ```

  The token comparison is performed with `secrets.compare_digest`
  (timing-safe).

- **Exempt paths** — the following routes are always reachable without a
  token:
  - `/api/health` — the health check endpoint
  - `/static/*` — static assets (CSS/JS/images)

Example authenticated call:

```bash
curl -H "Authorization: Bearer $WEB_AUTH_TOKEN" \
  http://127.0.0.1:8080/api/stats
```

!!! note "Configuration"

    Set `WEB_AUTH_TOKEN` in your `.env` file before starting the web server.
    See [Configuration](configuration.md) for the full environment reference.
