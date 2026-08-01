# VERIFIED.md — 1ai-osint verification status (honest assessment)

**Date:** 2026-08-01
**Repo:** `1ai-osint`, branch `main`, HEAD `712c5ba` (this document supersedes itself after each audit run; the current evidence set is dated 2026-08-01).

This file is the single source of truth for **what is verified, by what evidence,
and what is explicitly NOT verified**. It is written to be read by an auditor: every
claim names its receipt file and command. No claim here is an assertion of
"100% verified" — third-party independence is the one step this offline machine
cannot perform, and it is listed as such in §5.

---

## 1. Verified on this machine (reproducible, receipts on file)

### Correctness & safety engineering
| Claim | Evidence |
|---|---|
| Full test suite passes | `uv run pytest -q --tb=short` → **2462 passed, 8 skipped** (~107.19 s); receipt rows in `docs/evidence/MASTER_RECEIPT.md` §2 |
| Lint clean | `uv run ruff check src tests scripts` → `All checks passed!` |
| Types clean | `uv run mypy src` → no errors (301 source files) |
| Static security scan reviewed | `docs/evidence/security/bandit_2026-08-01.json` + `.txt` — **0 HIGH** after remediation; all 10 MEDIUM reviewed with verdicts (5 false positives, 2 intended, 2 vendored out-of-scope, 1 false positive) |
| Dependency CVE audit | `pip-audit` → 165 deps scanned; **1 advisory: `ecdsa` 0.19.2 → PYSEC-2026-1325 (no upstream fix)**; recorded in `docs/evidence/security/cve_scan_2026-08-01.txt` |

### Anti-fabrication
- Every outbound source call passes a **persisted token-bucket rate limiter**
  (`src/core/rate_limiter.py`; state at `.osint_rate_limit.json`).
- Findings carry **source + timestamp** metadata at creation; no synthesized data.
- **`DataLeaksAggregator` is properly wired** — all 6 key-gated providers load:
  `['hibp', 'leakcheck', 'scylla', 'breachdirectory', 'snusbase', 'intelx']`
  (verified: `DataLeaksAggregator()._get_providers().keys()`). Backends without a
  wired adapter are reported honestly empty, never faked.

### Runtime stability (soak)
- `scripts/soak.py` (rate-limiter + cache under synthetic load, 45 s, temp-dirs only):
  `docs/evidence/soak/receipt_2026-08-01.json`, schema `1ai-osint.soak.receipt.v1`,
  **verdict PASS**: 343,545 total calls, **0 errors**; rate_limiter 957/957 ok
  (avg 47.02 ms, p95 0.017 ms, max 1001.42 ms, 2 disk flushes, 0 reloads);
  cache 342,588/342,588 ok (avg 0.125 ms, p95 0.166 ms, max 4.05 ms, 685 prune passes).
- CI job: `.github/workflows/soak.yml` (manual + push to main), uploads the receipt artifact.

### Security controls
- **SSRF guard**: `deep_scraper` and `domain_recon` block private/internal targets.
- **XSS-escaping**: HTML/JSON dossier exports escape all data-derived values
  (empirically tested with hostile input).
- **Input validation / private-target blocking**: empty/malformed targets rejected (422),
  NIK structural checks, private-IP/domain blocklist.
- **Auth fail-closed option**: `REQUIRE_AUTH_TOKENS` → 401 for unauthenticated requests
  (live-verified, see MASTER_RECEIPT §3 Mode B); local-dev default fail-open documented.

### Performance (unit benchmarks, all external calls mocked)
Hash throughput 1,235,652 rec/s; graph resolution 0.04 ms/rec; correlation 0.0046 s;
memory 60.68 MB (limit 300 MB); ZKIT derivation 181.7 mnemonics/s (2.76× vs 65.8 baseline);
agent-vs-batch **6.22× wall-clock** with 13 API calls avoided. Full table: MASTER_RECEIPT §1.

---

## 2. Reviewed and accepted (documented, not fixed)

- **Bandit B704 (Markup)** ×5 — false positive: every data-derived value is escaped
  before wrapping; verified empirically. Verdicts in `docs/evidence/security/bandit_2026-08-01.txt`.
- **Bandit B104** ×2 — intended (CLI `--host 0.0.0.0` dashboard default, uvicorn dev entry).
- **Bandit B113** ×2 — vendored `src/vendor/chiasmodon/` (sync requests, key-gated, out of scope).
- LOW bandit findings (asserts, `try/except/pass`, `random` without crypto, subprocess) —
  review-only class; accepted with per-class rationale in the bandit evidence file.

---

## 3. Recorded, not hidden

- A prior benchmark receipt (`docs/evidence/benchmark/receipt_2026-08-01.json`) failed on
  real API errors (79 api_errors, 32.6% error rate) and is **kept as evidence**, not deleted.
- The single open dependency advisory (`ecdsa` 0.19.2, PYSEC-2026-1325, no upstream fix)
  is transitive and unfixable at our dependency level; recorded, not suppressed.

---

## 4. What "verified" means here — acceptance criteria

A claim counts as verified only if all of these hold:
1. It is backed by a literal receipt (command output or file) dated 2026-08-01.
2. The command is reproducible on this machine (`make ci` equivalent).
3. External services were mocked where live access is unavailable; no receipt
   pretends to be a live-source measurement.
4. Failures and caveats are recorded alongside successes.

## 5. Explicitly NOT verified (remaining steps before any "best in the world" claim)

- **Independent third-party audit** — every receipt above was produced by this repo's
  own tooling on this machine. An outside auditor (security review of threat model,
  adversarial review of the OSINT pipeline, independent benchmark reproduction) has
  not run.
- **Sustained soak** — the soak run was 45 s / 90.3 s wall. Multi-hour/multi-day soak
  with real API keys and real network traffic has not been run.
- **Live-source breadth** — real-world source freshness, uptime, regional coverage,
  and per-source hit rates cannot be certified from an offline machine.
- **Cross-vendor live benchmark** — head-to-head numbers against other tools on live
  data (see `docs/evidence/comparative-matrix.md` §6) are a market-research claim,
  not a code claim, and are not asserted.

> **Bottom line:** internally verified engineering quality (tests, lint, types, bandit,
> soak, performance, safety controls) with honest receipts — **not** independently
> verified. The last mile is a third-party audit and a live, keyed, sustained run.
