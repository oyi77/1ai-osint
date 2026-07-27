<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# free_intel

## Purpose
Free intelligence sources — gathers OSINT data from publicly accessible APIs and services without requiring API keys.

## Key Files
| File | Description |
|------|-------------|
| `github_intel.py` | GitHub public profile and repo intelligence |
| `google_dork_intel.py` | Google dork-based intelligence gathering |
| `gravatar_intel.py` | Gravatar profile lookup |
| `wayback_intel.py` | Wayback Machine historical data |
| `bts_intel.py` | BTS (telecom) intelligence |
| `pddikti_intel.py` | Indonesian higher education database lookup |
| `social_dorks_intel.py` | Social media dorking queries |
| `tech_jobs_intel.py` | Tech job platform intelligence |
| `hibp_free.py` | Have I Been Pwned free tier queries |
| `whatsapp_telegram_check.py` | WhatsApp/Telegram account verification |
| `ai_enricher.py` | AI enrichment for free intel results |
| `__init__.py` | Package initializer |

## For AI Agents

### Working In This Directory
- No API keys required — uses public endpoints and scraping
- Rate-limited to respect source terms of service

## Dependencies

### Internal
- `src/core/` — models, rate limiting, caching

<!-- MANUAL: -->
