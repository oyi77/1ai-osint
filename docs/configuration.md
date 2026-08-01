# Configuration

1ai-osint is configured through environment variables. Copy the template and
edit it:

```bash
cp .env.example .env
```

## OmniRoute AI Gateway

| Variable | Default | Description |
| --- | --- | --- |
| `OMNIRoute_BASE_URL` | `http://localhost:3000/v1` | Base URL for the OmniRoute OpenAI-compatible endpoint. |
| `OMNIRoute_API_KEY` | — | API key for OmniRoute (if required). |

## OpenAI (direct, fallback)

| Variable | Default | Description |
| --- | --- | --- |
| `OPENAI_API_KEY` | — | OpenAI API key (fallback when OmniRoute is not configured). |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL. |

## Breach / Leak Data Sources

| Variable | Description |
| --- | --- |
| `HIBP_API_KEY` | Have I Been Pwned |
| `SHODAN_API_KEY` | Shodan |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `WHOISXML_API_KEY` | WhoisXML |
| `CHIASMODON_TOKEN` | Chiasmodon |
| `DEHASHED_API_KEY` | DeHashed |
| `SCYLLA_API_KEY` | Scylla |
| `LEAKCHECK_API_KEY` | LeakCheck |
| `BREACHDIRECTORY_API_KEY` | BreachDirectory |
| `SNUSBASE_API_KEY` | Snusbase |
| `INTELX_API_KEY` | IntelX |

## GitHub

| Variable | Description |
| --- | --- |
| `GITHUB_TOKEN` | Token for gitleaks / GitHub dork scanning. |

## Twitter

| Variable | Description |
| --- | --- |
| `TWITTER_AUTH_TOKEN` | `auth_token` cookie value from x.com (via `twitter-cli`). |
| `TWITTER_CT0` | `ct0` cookie value from x.com. |

## ZKIT

| Variable | Description |
| --- | --- |
| `ZKIT_SALT` | Per-investigation salt for ZKIT identity hashing. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. |

## Telegram Alerts

| Variable | Description |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Bot token for Telegram alerts / node coordination. |
| `TELEGRAM_CHAT_ID` | Chat ID for alerts. |

## Webhook Alerts

| Variable | Description |
| --- | --- |
| `WEBHOOK_URL` | Webhook URL for alert delivery. |

## OSINT tooling

- `sherlock-project` is a core dependency (people_finder / username
  enumeration).
- Optional: `pip install maigret` — broader site coverage, slower.

## Application Settings

| Variable | Default | Description |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `CACHE_DIR` | `.osint_cache` | Cache directory (relative to project root). |
| `RATE_LIMIT_FILE` | `.osint_rate_limit.json` | Rate limit state file. |
| `AUDIT_LOG_PATH` | `.osint_audit.jsonl` | Compliance audit log — every adapter query is recorded here (tamper-evident, blueprint Layer 3). |
| `API_JOBS_DIR` | `state/jobs` | Directory where the API server persists running/finished scan jobs (empty = `<project_root>/state/jobs`). |
| `API_CORS_ORIGINS` | dev defaults | Comma-separated CORS origins allowed by the API server (empty = `http://localhost:5173`, `http://127.0.0.1:5173`). |
| `AI_OSINT_API_RPM` | `60` | Inbound per-client sustained rate (requests/minute) for the scan-creation endpoints (`POST /v1/scan`, `POST /api/scan`). Values below 1 are clamped to 1. |
| `AI_OSINT_API_BURST` | `30` | Inbound per-client burst before the API returns `429` + `Retry-After: 1` on scan-creation. Separate from the outbound per-source `RateLimiter` (`RATE_LIMIT_FILE`). |

> The API app also reads `AI_OSINT_JOBS_DIR` and `AI_OSINT_CORS_ORIGINS`
> directly from the environment; when set, those override
> `API_JOBS_DIR` / `API_CORS_ORIGINS` (see `src/api/app.py`).

## Database

| Variable | Default | Description |
| --- | --- | --- |
| `DB_TYPE` | `sqlite` | Database backend: `sqlite` or `postgres`. |
| `DB_PATH` | `1ai-osint.db` | SQLite database path (used when `DB_TYPE=sqlite`). |
| `DB_HOST` | `localhost` | Postgres host. |
| `DB_PORT` | `5432` | Postgres port. |
| `DB_NAME` | `osint` | Postgres database name. |
| `DB_USER` | `osint` | Postgres user. |
| `DB_PASSWORD` | — | Postgres password. |

## Web UI

| Variable | Default | Description |
| --- | --- | --- |
| `WEB_AUTH_TOKEN` | — | Optional bearer token protecting the web dashboard. When set, every route except `/api/health`, `/static`, and `/api/auth/login` requires `Authorization: Bearer <WEB_AUTH_TOKEN>`. When empty/unset, the web UI runs unauthenticated (local dev default) and unauthenticated callers are treated as `READONLY` tier (least privilege). |
| `WEB_AUTH_TOKENS` | — | Multi-tier bearer tokens as `tier:token,tier:token` (e.g. `readonly:tok1,admin:tok2`). Overrides the legacy `WEB_AUTH_TOKEN` for per-tier RBAC (tiers: `readonly`, `analyst`, `admin`). |
| `REQUIRE_AUTH_TOKENS` | — | Fail-closed auth switch (`1`, `true`, or `yes`). Forces authentication even when no tokens are configured — every non-exempt route is then rejected with 401. Without it, an unauthenticated deployment stays open (local dev default) but runs at `READONLY` tier. |

See [Web UI](web-ui.md) for the authentication behavior in detail.

## Master Node API (distributed coordination)

| Variable | Default | Description |
| --- | --- | --- |
| `MASTER_API_TOKEN` | — | Bearer token for the master coordination API (`src/modules/node/master_api.py`). When unset, the node API stays open (backward-compatible local dev default) and a warning is logged. Set a strong token for any shared/distributed deployment. |
