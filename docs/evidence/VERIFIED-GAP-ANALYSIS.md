# VERIFIED-GAP-ANALYSIS.md — what stands between this repo and an externally verifiable "best" claim

**Date:** 2026-08-02
**Purpose:** operationalize `docs/VERIFIED.md` §5. This file turns each "explicitly
NOT verified" item into a runnable, auditable plan: what is needed, the exact
procedure and commands, the acceptance criteria, who runs it, and current status.

This file does **not** assert that the gaps are closed. As of 2026-08-02 the
internal engineering half of each gap is materially advanced (reproducible
gate, receipts, harnesses, cron schedules), but the external half of each gap
remains open: an independent third-party audit, a live keyed ≥24 h soak, a ≥7
day live-source corpus, and an identical-target cross-vendor race — none of
which a single offline machine can produce on its own.

---

## Source of truth (verbatim from `docs/VERIFIED.md` §5)

> - **Independent third-party audit** — every receipt above was produced by this repo's
>   own tooling on this machine. An outside auditor (security review of threat model,
>   adversarial review of the OSINT pipeline, independent benchmark reproduction) has
>   not run.
> - **Sustained soak** — the soak run was 45 s / 90.3 s wall. Multi-hour/multi-day soak
>   with real API keys and real network traffic has not been run.
> - **Live-source breadth** — real-world source freshness, uptime, regional coverage,
>   and per-source hit rates cannot be certified from an offline machine.
> - **Cross-vendor live benchmark** — head-to-head numbers against other tools on live
>   data (see `docs/evidence/comparative-matrix.md` §6) are a market-research claim,
>   not a code claim, and are not asserted.

> **Bottom line:** internally verified engineering quality (tests, lint, types, bandit,
> soak, performance, safety controls) with honest receipts — **not** independently
> verified. The last mile is a third-party audit and a live, keyed, sustained run.

---

## Gap 1 — Independent third-party audit

**What's needed:** an auditor external to this repo runs the verification, not the
repo's own tooling. Scope: (a) security review of the threat model, (b) adversarial
review of the OSINT pipeline (anti-fabrication, rate limiting, SSRF guards,
XSS-escaping, auth fail-closed), (c) independent reproduction of the benchmark
receipts.

**Procedure + commands (for the auditor):**
```bash
git clone <repo-url> && cd 1ai-osint
uv sync && uv run make ci          # lint → typecheck → full test suite
uv run ruff check src tests scripts
uv run mypy src
uv run bandit -r src -f json -o bandit_audit.json   # compare vs docs/evidence/security/bandit_2026-08-01.json
uv run pytest -q --tb=short        # compare vs docs/evidence/MASTER_RECEIPT.md §2
uv run python scripts/soak.py      # compare vs docs/evidence/soak/receipt_2026-08-01.json
# adversarial pass: attempt SSRF against private targets, hostile HTML/JSON dossier input,
# unauthenticated requests with REQUIRE_AUTH_TOKENS=1 — all must be blocked/escaped/401.
```

**Acceptance criteria:** auditor issues a written verdict; every repo receipt
reproduces within tolerance on the auditor's machine; no HIGH-severity finding
unaccounted for; adversarial tests all pass; verdict stored as
`docs/evidence/audit/<auditor>_<date>.md`.

**Who runs it:** external security reviewer / independent OSINT practitioner.
**Effort:** 2–5 person-days.
**Status:** **PARTIAL** — internal gate shipped 2026-08-02: `scripts/audit_runner.sh`
runs lint → typecheck → scripts lint/typecheck → bandit (fail on HIGH) → full
pytest → 30 s soak → adversarial suite, all green, receipts regenerated under
`docs/evidence/audit/` (summary_2026-08-02.txt, bandit_2026-08-02.json,
adversarial_2026-08-02.json, soak_2026-08-02.json). The independent
third-party pass itself is **NOT STARTED** — blocked on engaging an auditor.

---

## Gap 2 — Sustained soak (live, keyed, multi-hour/day)

**What's needed:** the current soak (`scripts/soak.py`) is 45 s / 90.3 s wall with
mocked traffic. The gap is a sustained run — hours to days — under real API keys,
real network egress, and real rate-limit pressure.

**Procedure + commands:**
```bash
# long-run mode (extend scripts/soak.py or drive it on a schedule; record start/end)
timeout 86400 uv run python scripts/soak.py --long-run --keys "$REAL_KEYS" --network
# capture per-source call counts, errors, rate-limit hits, cache hit rates at ~10 min granularity
# CI: .github/workflows/soak.yml already uploads the receipt artifact; add a scheduled nightly job
```

**Acceptance criteria:** ≥24 h continuous run, zero unhandled errors, all
rate-limiter and cache invariants hold (compare vs the 957/957 and 342,588/342,588
baselines in `docs/VERIFIED.md` §1), receipts stored under
`docs/evidence/soak/live/`.

**Who runs it:** repo maintainer on a machine with real keys + network (or CI cron).
**Effort:** 1–2 days setup + runtime.
**Status:** **IN PROGRESS** — harness shipped 2026-08-02: `scripts/soak.py`
extended with `--long-run --network --json`, a 1 h live soak is/was running from
this session (receipt under `docs/evidence/soak/live/`), and a nightly soak cron
(`.github/workflows/soak.yml`) accumulates receipts. The ≥24 h keyed continuous
run is **open** — blocked on real API keys on a sustained networked host.

---

## Gap 3 — Live-source breadth certification

**What's needed:** certify real-world source freshness, uptime, regional coverage,
and per-source hit rates — impossible from an offline machine. The automated probe
(`scripts/source_baseline.py`, receipts under `docs/evidence/live/`) is the
harness; it must run from a networked host on a schedule and accumulate a corpus.

**Procedure + commands (on a networked host):**
```bash
uv run python scripts/source_baseline.py            # probes every active source, writes source_probe_<rev>.json/.md
# schedule: nightly cron or CI cron job; append each probe to a history table
# then analyze: uptime % per source, failure classes (404/rate-limit/geo-block/parse), hit rates by category
```

**Acceptance criteria:** ≥7 days of consecutive probe data; a published table of
per-source uptime and hit rate; any source failing >N% of probes is marked
degraded in the registry or removed; receipt under `docs/evidence/live/` updated.

**Who runs it:** repo maintainer or CI cron on a networked host.
**Effort:** 1 day setup + 1 week runtime.
**Status:** **IN PROGRESS** — harness + corpus seed shipped 2026-08-02:
`scripts/source_baseline.py` now appends probe history and computes uptime;
first runs on 2026-08-01/02 probed 63 sources (latest `f73d4f2` run: 27
verified-live / 12 reachable-no-data / 13 failed / 11 tool-skipped; overall
uptime 75.0%; hit rates api 50.0% / re 54.8% / scrape 33.3%; receipts under
`docs/evidence/live/` incl. `uptime_report.md` and `history.json`); a nightly
live-probe cron (`.github/workflows/live-probe.yml`) is scheduled. The ≥7 day
consecutive corpus is **open** — only a single day of data exists so far.

---

## Gap 4 — Cross-vendor live benchmark

**What's needed:** head-to-head numbers against other OSINT tools on live data:
Sherlock/Maigret (username breadth), Holehe (email→account), theHarvester
(org→domains), SpiderFoot (module coverage), plus keyless subdomain/crypto/feed
sets. This is a market-research claim (`docs/evidence/comparative-matrix.md` §6),
not a code claim.

**Procedure + commands:**
```bash
# same target set, live network, same host/keys where applicable:
uv run python scripts/live_benchmark.py --json --targets tests/fixtures/live_targets.json
uv run python scripts/benchmark_agent_vs_batch.py
# run the comparable open-source tools against the same targets:
python -m sherlock --print-found --json <username>   # + maigret, holehe, theharvester, spiderfoot CLI
# produce a table: per category — sources probed, hit rate, latency, keyless vs keyed
```

**Acceptance criteria:** a dated, reproducible table comparing 1ai-osint vs each
tool on identical targets; methodology documented; results stored under
`docs/evidence/comparative/`.

**Who runs it:** repo maintainer or independent benchmarker on a networked host.
**Effort:** 1–3 days.
**Status:** **IN PROGRESS** — live-run receipts shipped 2026-08-02 under
`docs/evidence/comparative/` via `scripts/live_benchmark.py`: 1ai-osint
keyless `octocat` (120 findings / 0 critical / 57.9 s), sherlock (114 hits /
70.0 s), maigret (237 markers / 196.1 s), holehe (1 used / 11.4 s), theHarvester
(timeout / 0 / 120.0 s), plus per-tool scorecards and a README that documents
the honest methodology (different targets per tool, tool-dependent counts,
non-head-to-head). The identical-target, cross-vendor **race is not asserted** —
it needs the methodology items listed as still open.

---

## Summary

| Gap | Status | Blocker |
|---|---|---|
| 1. Independent third-party audit | PARTIAL | third-party engagement (internal gate shipped) |
| 2. Sustained soak (live, keyed) | IN PROGRESS | real keys + ≥24 h sustained networked host |
| 3. Live-source breadth certification | IN PROGRESS | ≥7-day accumulated probe corpus |
| 4. Cross-vendor live benchmark | IN PROGRESS | identical-target, cross-vendor live race |

Until all four are closed **with receipts**, the correct claim remains exactly the
`docs/VERIFIED.md` bottom line: *internally verified engineering quality with
honest receipts — not independently verified.*
