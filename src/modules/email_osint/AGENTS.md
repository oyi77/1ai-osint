---
scope: email_osint
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# email_osint

> Last updated: correct stale DeHashed/Chiasmodon breach-source claim (commit 8fa2bbf)

## Purpose
Email OSINT — breach lookup, email validation, and associated account/domain discovery.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Full `EmailOSINTTool` implementation (246 lines) — breach lookup, social/account discovery, domain TXT analysis |

## For AI Agents

### Working In This Directory
- Breach lookup (`_check_breaches`) queries `https://haveibeenpwned.com/unifiedsearch/{email}` directly via httpx — no API key header, no DeHashed/Chiasmodon
- `_check_social_media` uses the GitHub search API for account discovery
- `_analyze_domain` resolves email domain TXT records via dns.google
- Results feed into ZKIT identity correlation

## Dependencies

### Internal
- `src/core/` — models and config

<!-- MANUAL: -->
