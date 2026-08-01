# Independent Audit Checklist — 1ai-osint

This checklist is the **third-party verification contract** for the claim in
[`docs/VERIFIED.md`](../VERIFIED.md). It tells an independent auditor exactly
what to reproduce, what to inspect, and what evidence must exist before the
claim can be marked **verified**.

An auditor should be able to take this document, run every command below on a
clean checkout, and independently confirm or refute each exit-criterion row.

---

## 1. Purpose & How to Use

- **Auditor**: work through §4 (reproduce) and §5 (inspect) in order. Fill in
  §7's exit-criteria table. Leave a signed report (template in §9).
- **Maintainers**: re-run §4 before every release. Any new finding updates
  `docs/evidence/` and the bandit disposition table in §5.2.
- **Scope of the claim**: the claim is about the *engine* — detection quality,
  correctness of results, safety under load, and absence of known high-severity
  flaws — not about marketing copy. Where evidence is still missing, the claim
  stays **unverified for that row** and `docs/VERIFIED.md` must say so.

---

## 2. Scope & Baseline

| Item | Value |
|------|-------|
| Repository | `https://github.com/oyi77/1ai-osint.git` |
| Branch | `main` |
| Baseline HEAD | `8d677fb13517d45b8a13f13f01a6268ba9f6e86a` (evidence was generated at or after this commit) |
| Primary language | Python 3.10+ (async/await throughout) |
| Included | `src/`, `tests/`, `scripts/` |
| Excluded | `frontend/`, `output/` (generated), `notebooks/` (exploratory), `site/` (built docs) |

> Baseline HEAD is the commit at which the current evidence set was produced.
> Evidence generated from a different HEAD should be re-generated or annotated.

---

## 3. Environment

- Python ≥ 3.10, `uv` (project uses `uv` for env + tools).
- External tools needed for the live benchmark are optional; `detect` mode
  reports their absence without failing (see §4.8).

---

## 4. Reproduction Commands

Run each; record the actual output. Expected results are stated per command.

```bash
# 4.1  Unit / integration test suite
rm -f .coverage                      # repo convention: stale .coverage corrupts runs
uv run pytest -q --tb=short
# EXPECT: ~2462 passed, 8 skipped, 0 failed (verified at baseline)

# 4.2  Lint (whole project)
uv run ruff check src/ tests/ scripts/
# EXPECT: no errors

# 4.3  Type check
uv run mypy src/
# EXPECT: no errors (Makefile `typecheck` target)

# 4.4  Static security scan (SAST)
uvx bandit -r src -q -f json -o /tmp/bandit.json
# EXPECT: 0 HIGH; MEDIUM findings each have a documented verdict (see §5.2)
#   archive: docs/evidence/security/bandit_2026-08-01.{json,txt}

# 4.5  Dependency vulnerability scan (SCA)
uv run pip-audit
# EXPECT: 0 high/critical. Baseline advisory (see §5.3):
#   ecdsa 0.19.2  PYSEC-2026-1325
#   archive: docs/evidence/security/cve_scan_2026-08-01.txt

# 4.6  Rate limiter + cache soak (network-free)
uv run python scripts/soak.py --duration 45 --json > /tmp/soak_receipt.json 2> /tmp/soak_report.txt
# EXPECT: verdict "PASS", total_errors == 0
#   baseline: 343,545 calls / 0 errors
#   archive: docs/evidence/soak/receipt_2026-08-01.json

# 4.7  Performance benchmark (network-free, synthetic)
uv run python scripts/benchmark.py --json > /tmp/bench_receipt.json 2> /tmp/bench_report.txt
# EXPECT: completes; receipt valid JSON
#   archive: docs/evidence/benchmark/receipt_2026-08-01.json
#   (kept as honest evidence of a failed live API run — see §6, "known limitations")

# 4.8  Live tool breadth benchmark — detect mode (network-free)
uv run python scripts/live_benchmark.py --target testuser --json > /tmp/lb_receipt.json 2> /tmp/lb_report.txt
# EXPECT: exit 0; valid JSON receipt on stdout; stderr lists each tool
#   installed/missing. Baseline: 1ai-osint + theHarvester + spiderfoot +
#   recon-ng installed; sherlock/maigret/holehe/maltego missing.

# 4.9  Live tool breadth benchmark — live mode (NEEDS NETWORK + API KEYS)
uv run python scripts/live_benchmark.py --target <authorized-target> --mode live \
    --scan-timeout 60 --tool-timeout 120 --scorecard /tmp/sc.md \
    --json > /tmp/lb_live_receipt.json 2> /tmp/lb_live_report.txt
# EXPECT: verdict COMPARED (1ai-osint + >=1 external tool ran), or INCOMPLETE
#   with a clear note of which tools failed and why.
# NOTE: this is the one command NOT yet executed end-to-end (see §6).
#   Run it only against targets you are authorized to scan.
```

---

## 5. Code-Review Areas

### 5.1 Correctness

| Area | What to verify | Where |
|------|----------------|-------|
| Result identity | Every `Finding` / `ScanResult` carries `id` and `scan_id` | `src/core/models/` |
| Cache semantics | `cache.has()` returns only verified-present entries; no stale "present" on miss | `src/core/cache.py` |
| Rate limiting | All external calls go through `rate_limiter.py`; limits persist to disk and reload | `src/core/rate_limiter.py` |
| Honest aggregation | Empty results are reported as empty — no fabricated findings, no hallucinated sources | `src/core/aggregator*`, module `run()` paths |
| SSRF guard | `domain_recon` / `social_osint` validate and constrain URLs/IPs before fetching | `src/modules/domain_recon/`, `src/modules/social_osint/` |
| XSS escaping | HTML reports escape every data-derived value (no raw `<script>` reachable) | `src/web/html_export.py` (see bandit B704 disposition) |
| Auth fail-closed | Web/API endpoints deny by default; auth errors close, never open | `src/web/`, `src/api/` |

### 5.2 Static security (bandit) — disposition of MEDIUM findings

Total: **HIGH 0 · MEDIUM 10 · LOW 113**. MEDIUM verdicts:

| Test id | Count | Verdict |
|---------|-------|---------|
| B704 `markupsafe.no_escape` | 5 | False positive — content is escaped before `Markup()` wrap (verified empirically, `html_export.py:53,54,120,138,173`) |
| B608 SQL f-string | 1 | False positive — interpolates module-level constant only (`ai_analyzer.py:131`) |
| B104 bind 0.0.0.0 | 2 | Intended — user-invoked dashboard (`config_commands.py:122`, `web/main.py:13`) |
| B113 request without timeout | 2 | Out of scope — vendored third-party tooling (`src/vendor/chiasmodon/hibp/__init__.py:19`, `shodan/__init__.py:19`) |

LOW findings are review-only: B311 = non-security randomness, B110/B112 =
intentional best-effort error handling, B404/B603/B607 = `shell=False`
subprocess with fixed argv, B105/B107 = example/default strings, B101 = asserts.

### 5.3 Dependency advisory

- `ecdsa 0.19.2` — `PYSEC-2026-1325`. No fix version published at evidence time.
  Exposure is limited: ecdsa is used only for crypto-key fingerprinting of
  scanned artifacts, not for signing/trust decisions in this tool. Track and
  bump when a fix lands. Full output: `docs/evidence/security/cve_scan_2026-08-01.txt`.

### 5.4 Architecture

| Convention | Verify |
|------------|--------|
| All modules async/await | no sync-blocking I/O in `src/modules/**` hot paths |
| Pydantic models for all data shapes | `id` + `scan_id` on Finding/ScanResult |
| Plugin registration | via `__init__.py` exports (no side-effect imports) |
| Rate limiting | every external API hit passes `rate_limiter.py` |
| Caching | `cache.py` dedups repeated lookups; tests mock external APIs, never call real endpoints |

---

## 6. Known Limitations (do not hide these)

1. **Live breadth run not yet executed** — `scripts/live_benchmark.py` is the
   harness (verified in `detect` mode, §4.8), but a full `--mode live` run with
   API keys against an authorized target is still outstanding. Until it runs,
   the cross-tool comparison claim is **unverified**.
2. **No sustained live soak** — the soak is network-free (rate limiter + cache).
   Long-duration live API load has not been run.
3. **Third-party audit not yet performed** — this checklist is the *contract*
   for it; an independent auditor has not yet signed off.
4. **API keys required** — live modules (e.g. HIBP, Shodan-class sources) need
   keys; without them live breadth is partial. This is environmental, not a
   code defect.

---

## 7. Exit Criteria

| # | Claim | Evidence to inspect | Pass |
|---|-------|---------------------|------|
| 1 | Full test suite green | §4.1 output: 2462 passed / 8 skipped / 0 failed | ☐ |
| 2 | Lint + type clean | §4.2, §4.3 output | ☐ |
| 3 | No known HIGH-severity static findings | §4.4 + `bandit_2026-08-01.txt` (HIGH 0, MEDIUM documented) | ☐ |
| 4 | Dependency advisories triaged | §4.5 + `cve_scan_2026-08-01.txt` (1 advisory, exposure-limited) | ☐ |
| 5 | Rate limiter + cache survive soak | §4.6 receipt: PASS, 0 errors | ☐ |
| 6 | Engine honest under load | aggregator/scan results contain no fabricated findings | ☐ |
| 7 | Live breadth compared | §4.9 receipt: verdict COMPARED | ☐ |
| 8 | Independent audit performed | Signed report per §9 appended to `docs/evidence/` | ☐ |

Rows 1–6 currently have evidence. **Row 7 and Row 8 are open.** The claim in
`docs/VERIFIED.md` is accordingly phrased as "verified internally; external
verification pending" until rows 7–8 close.

---

## 8. Severity Definitions

- **HIGH** — exploitable remote/unauthorized impact, or data corruption.
- **MEDIUM** — exploitable under conditions (auth, config, vendored code), or
  defense-in-depth gap.
- **LOW** — style, best-practice, review-only.
- **UNVERIFIED** — no evidence yet; the row stays open until reproduced.

---

## 9. Audit Report Template

```markdown
# Independent Audit Report — 1ai-osint

- Auditor: <name / org>
- Date: <ISO>
- Checkout: <commit hash audited>
- Environment: <python/uv/os>

## Reproduction
| Command (§4) | Result | Matches expected? |
|--------------|--------|-------------------|
| pytest | <n passed / n skipped / n failed> | ☐ |
| ruff | ... | ☐ |
| mypy | ... | ☐ |
| bandit | ... | ☐ |
| pip-audit | ... | ☐ |
| soak | ... | ☐ |
| live_benchmark detect | ... | ☐ |
| live_benchmark live | ... | ☐ |

## Code review
<findings per §5 area; each with severity + file:line + recommendation>

## Exit criteria (§7)
<check rows 1–8; for any ☐ unmarked, state the gap>

## Verdict
<OVERALL: VERIFIED / CONDITIONALLY VERIFIED / NOT VERIFIED + signature>
```
