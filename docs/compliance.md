# Compliance Layer

> Blueprint Layer 3 — Access Control & Compliance. Implemented as Phase 0 of
> the [blueprint gap analysis](blueprint-gap-analysis.md).
>
> **Goal:** compliance-by-design is a *feature*, not an afterthought
> (blueprint §1.3). Every data source carries a documented legal basis, and
> every query is recorded in a central audit trail.

## Why this exists

The August 2026 BerkahKarya blueprint defines "best in the world" OSINT
across 5 axes, one of which is **trust & compliance** (UU PDP — Law
27/2022, fully enforced since October 2024). The gap analysis flagged
Layer 3 at ~25%: auth + partial audit trail existed, but legal-basis
tagging, retention, and consent gating did not.

## What was built (Phase 0)

### S1 — Legal-basis registry (`src/core/compliance.py`)

Every source has a `LegalBasis`:

| Legal basis | Meaning |
| --- | --- |
| `government_open_data` | Public government data (e.g. PDDIKTI) — safest basis |
| `legitimate_interest` | Publicly available data via OSINT tooling |
| `consent` | Requires explicit consent (Pasal 4.2 UU PDP categories) |
| `public_api_tos` | Official API with documented ToS (HIBP, GitHub, …) |
| `undocumented` | **No legal basis documented — gap is visible, not assumed** |

- 78 sources are backfilled (see `registered_sources()`), including the
  open-government adapters `pandi_whois_intel`, `data_go_id_intel` and
  `pddikti_intel` tagged `government_open_data` (blueprint Phase 2 S5).
- Unknown sources **default to `undocumented`** so the gap surfaces in the
  audit trail instead of being silently assumed compliant.
- Paid breach DBs (dehashed, intelx, leakcheck, snusbase, snylla) are
  explicitly flagged `undocumented` with a legal-review note (blueprint §3
  ⛔ category).
- `requires_consent` flag exists for Pasal 4.2 sensitive categories
  (health, biometrics, children's data, …). No adapter is built for these.

### S2 — Central audit log

Every query through `run_source_scan()` (the breach/leak source adapter)
records one JSONL entry:

```json
{
  "id": "audit-12889cebc9de",
  "timestamp": "2026-07-31T20:43:36.542881Z",
  "source": "hibp",
  "target": "demo@x.com",
  "legal_basis": "public_api_tos",
  "requester": "deep_scan_engine",
  "outcome": "ok",
  "findings_count": 2,
  "retention_days": 30
}
```

- **Outcomes:** `ok` / `empty` / `error` / `blocked`
- **Consent gate:** a source flagged `requires_consent` is blocked *before*
  any query is made, and the block itself is audited.
- **Retention:** default 30 days (Sherlockeye standard, blueprint §4.5);
  `purge_expired_audit_entries()` enforces it.
- **Config:** log path via `AUDIT_LOG_PATH` env var (default
  `.osint_audit.jsonl`).

## Usage

```python
from src.core.compliance import (
    get_compliance, record_audit, read_audit_entries,
    purge_expired_audit_entries, registered_sources,
)

# What legal basis does this source have?
comp = get_compliance("hibp")          # LegalBasis.PUBLIC_API_TOS

# Everything querying a source goes through record_audit().
record_audit(source="hibp", target="x@y.com",
             requester="my-tool", outcome="ok", findings_count=3)

# Read / purge
entries = read_audit_entries(limit=100)
purged = purge_expired_audit_entries()
```

## Roadmap (still open — Phase 0b)

- RBAC per user tier
- ToS guard per source (rate-limit awareness per platform ToS)
- Retention policy UI/API endpoint
- Wire free-intel adapter through the same audit gate

## Verification

```bash
uv run pytest tests/unit/test_compliance.py -q   # 21 tests
uv run mypy src/                                  # 0 errors
uv run ruff check src/ tests/                     # 0 errors
```
