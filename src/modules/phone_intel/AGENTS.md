---
scope: phone_intel
depends_on:
  - src/core
  - src/modules/phone_finder
status: complete
---
<!-- Parent: ../AGENTS.md -->

# phone_intel

> Last updated: broadened to WhatsApp OSINT + Hudson Rock correlation (commit 9c9246c)

## Purpose
Aggregated phone intelligence from multiple sources into one local SQLite DB.
Each source has a per-source TTL; fresh entries are served from the DB so
limited/quota-billed sources (getcontact) are called once per phone per TTL.

## Key Files
| File | Description |
|------|-------------|
| `db.py` | SQLite store (`state/phone_intel.db`, env `PHONE_INTEL_DB`) — `phone_lookups(phone, source, data, status, fetched_at, expires_at)` PK(phone, source); get/save/upsert/query_phone/list_phones/count; thread-safe, stdlib sqlite3 |
| `__init__.py` | `PhoneIntelTool` (BaseOSINTTool) — aggregates sources in order: getcontact → web → carrier → truecaller → whatsapp; each fetched if not fresh in DB, then persisted; Hudson Rock correlation runs when the GetContact profile reveals an email |
| `web_search.py` | `PhoneWebSearch` — DuckDuckGo HTML search (`html.duckduckgo.com` + `lite`) for public pages mentioning the phone; free, no key |
| `carrier.py` | `PhoneCarrierLookup` — omkarcloud phone-lookup-api (`carrier-lookup-api.omkar.cloud`, `API-Key` header); carrier/line-type/validity; key-gated `OMKAR_PHONE_API_KEY` |
| `truecaller.py` | `TruecallerLookup` — unofficial Truecaller v2 search endpoint; gated `TRUECALLER_TOKEN`; fragile, use at own risk |
| `whatsapp_osint.py` | `WhatsAppOSINT` — presence via `wa.me` (always); status/photo/business profile via unofficial WhatsApp Web endpoint when `WHATSAPP_WEB_TOKEN` is set (gated, fragile) |

## Correlation chain
phone → **getcontact** (profile + tags) → email found? → **Hudson Rock** infostealer
breach query (`src/modules/data_leaks/hudson_rock.py`, free API, cached 30d).

## For AI Agents
- Register as `phone_intel` (alias `phoneintel`); CLI: `1ai-osint phone_intel +628...`
- TTLs: getcontact/web/whatsapp 7d; carrier/truecaller/hudson 30d
- Sources that lack credentials (truecaller, carrier, whatsapp token) return
  empty data and are stored/skipped — they never break the others
- GCLookupTool (`src/modules/phone_finder/gc_lookup.py`) accepts `db_path` and
  persists its own getcontact results into the same DB (lazy import, no cycle)
- Tests: `tests/unit/test_phone_intel_db.py`, `tests/unit/test_phone_intel.py`

## Dependencies
### Internal
- `src/core/` — models (Finding, ScanResult, Severity)
- `src/utils/phone_normalize.py` — E.164 normalization
- `src/modules/phone_finder/gc_lookup.py` — GetContact CLI wrapper (getcontact source)
- `src/modules/data_leaks/hudson_rock.py` — infostealer correlation
### External
- `gc-lookup` binary (github.com/oyi77/gc-lookup) — GetContact protocol client
- omkarcloud phone-lookup-api (key), Truecaller/WhatsApp Web (unofficial tokens)
