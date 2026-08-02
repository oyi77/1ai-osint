# VERIFIED-GAP-ANALYSIS.md — what stands between this repo and an externally verifiable "best" claim

**Date:** 2026-08-01
**Purpose:** operationalize `docs/VERIFIED.md` §5. This file turns each "explicitly
NOT verified" item into a runnable, auditable plan: what is needed, the exact
procedure and commands, the acceptance criteria, who runs it, and current status.

This file does **not** assert that the gaps are closed. All four items are
**NOT STARTED**; each is blocked on one of two external preconditions:
an independent third party, or a live, keyed, sustained network run — neither of
which an offline single-machine repo can satisfy on its own.

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
**Status:** **NOT STARTED** — blocked on engaging a third party.

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
**Status:** **NOT STARTED** — blocked on real keys and a network-connected host.

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
**Status:** **NOT STARTED** — first live probe run is in flight from this session;
no accumulated corpus yet.

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
**Status:** **NOT STARTED** — blocked on live network + installed competitor CLIs.

---

## Summary

| Gap | Status | Blocker |
|---|---|---|
| 1. Independent third-party audit | NOT STARTED | third-party engagement |
| 2. Sustained soak (live, keyed) | NOT STARTED | real keys + networked host |
| 3. Live-source breadth certification | NOT STARTED (first probe in flight) | networked host + accumulated corpus |
| 4. Cross-vendor live benchmark | NOT STARTED | networked host + competitor CLIs |

Until all four are closed **with receipts**, the correct claim remains exactly the
`docs/VERIFIED.md` bottom line: *internally verified engineering quality with
honest receipts — not independently verified.*
