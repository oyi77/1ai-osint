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

## Web UI

| Variable | Default | Description |
| --- | --- | --- |
| `WEB_AUTH_TOKEN` | — | Optional bearer token protecting the web dashboard. When set, every route except `/api/health` and `/static` requires `Authorization: Bearer <WEB_AUTH_TOKEN>`. When empty/unset, the web UI runs unauthenticated (local dev default). |

See [Web UI](web-ui.md) for the authentication behavior in detail.
