---
scope: phone_finder
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# phone_finder

> Last updated: document two code paths (direct PhoneInfoga API vs chiasmodon provider) (commit 8fa2bbf)

## Purpose
Phone number lookup and enrichment — carrier, location, and linked-account OSINT.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | `PhoneFinderTool` (line 14, 145 lines) — direct httpx calls to a PhoneInfoga server (`{phoneinfoga_url}/api/v1/numbers/{phone}`, default `http://localhost:3000`), scam-report findings (HIGH), basic-validation fallback (status "partial") |
| `lookup.py` | `PhoneFinderLookup` (line 33) — wraps `src.vendor.chiasmodon.providers.phoneinfoga.PhoneInfogaProvider`; E.164 validation via `src.utils.phone_normalize` (default region ID); offline `lookup_id_carrier` fallback for +62 numbers; carrier/VoIP/location findings |

## For AI Agents

### Working In This Directory
- Both entry points normalize numbers with `normalize_phone_e164(default_region="ID")`; `PhoneFinderLookup.validate_e164` is a static helper
- `PhoneFinderTool` needs a reachable PhoneInfoga instance; tanpa itu ia jatuh ke validasi dasar — hanya bila target ternormalisasi sebagai nomor valid ia mengeluarkan INFO record (`__init__.py:118-129`); bila target bukan nomor valid, ia return lebih awal dengan `status="partial"`, `findings=[]`, dan metadata note "Target is not a valid phone number; PhoneInfoga unreachable" (`__init__.py:102-116`) — tidak ada finding fabrikasi untuk input non-phone
- Tests: `tests/unit/test_phone_finder.py`, `tests/unit/test_phone_finder_tool.py`

## Dependencies

### Internal
- `src/core/` — models
- `src/utils/phone_normalize.py` — E.164 normalization
- `src/vendor/chiasmodon/` — PhoneInfoga provider (via `lookup.py`)

<!-- MANUAL: -->
> Last updated: fix pass — tidak ada finding fabrikasi untuk input non-phone; return awal `status="partial"` + `findings=[]` + metadata note bila target bukan nomor valid (`__init__.py:102-116`); INFO record dasar hanya untuk nomor valid saat PhoneInfoga unreachable (`:118-129`)
