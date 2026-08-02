---
scope: free_intel
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# free_intel

> Last updated: add missing DataGoId/PandiWhois files, qualify API-key claim (commit 8fa2bbf)

## Purpose
Free intelligence sources — gathers OSINT data from publicly accessible APIs and services. Keyless by default; a few sources accept optional keys for higher tiers.

## Key Files
| File | Description |
|------|-------------|
| `github_intel.py` | `GitHubIntel` (line 34) — GitHub public profile and repo intelligence |
| `google_dork_intel.py` | `GoogleDorkIntel` (line 23) — Google dork-based intelligence gathering |
| `gravatar_intel.py` | `GravatarIntel` (line 22) — Gravatar profile lookup |
| `wayback_intel.py` | `WaybackIntel` (line 17) — Wayback Machine historical data |
| `bts_intel.py` | `BTSIntel` (line 81) — BTS (telecom) intelligence |
| `pddikti_intel.py` | `PDDIKTIIntel` (line 19) — Indonesian higher education database lookup |
| `social_dorks_intel.py` | `SocialDorksIntel` (line 50) — social media dorking queries |
| `tech_jobs_intel.py` | `TechJobsIntel` (line 19) — tech job platform intelligence |
| `hibp_free.py` | `HIBPIntel` (line 24) — Have I Been Pwned queries; `HIBP_API_KEY` optional ("not set — using limited breach check") |
| `whatsapp_telegram_check.py` | `MessagingIntel` (line 18) — WhatsApp/Telegram account verification |
| `ai_enricher.py` | `AIExtractor` (line 33) — AI enrichment; `OPENAI_API_KEY` or `OMNIROUTE_API_KEY` optional |
| `data_go_id_intel.py` | `DataGoIdIntel` (line 41) — data.go.id dataset search |
| `pandi_whois_intel.py` | `PandiWhoisIntel` (line 108) — Indonesian PANDI RDAP lookups (`PandiWhoisRecord` line 32) |
| `__init__.py` | Docstring only — no exports (classes are imported directly) |

## For AI Agents

### Working In This Directory
- No API keys required by default — public endpoints and scraping
- `HIBP_API_KEY` (hibp_free.py) and `OPENAI_API_KEY`/`OMNIROUTE_API_KEY` (ai_enricher.py) are optional keys, referenced by env var only
- Rate-limited to respect source terms of service

## Dependencies

### Internal
- `src/core/` — models, rate limiting, caching

<!-- MANUAL: -->
