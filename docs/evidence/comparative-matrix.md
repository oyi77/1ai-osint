# Comparative Matrix — 1ai-osint vs Industry OSINT Tools

**Date:** 2026-08-01
**Type:** Structural comparison (capability-by-capability), based on each tool's documented feature set and this repository's source. Not a live head-to-head: live source availability differs by region, licensing, and rate limits, and those cannot be certified offline.

---

## 1. Agent vs Batch Evidence (this repo, deterministic run)

Captured from `scripts/benchmark_agent_vs_batch.py` (all external calls mocked, no network) — see `agent_vs_batch_run.txt`.

| Metric | Naive batch | S4 agent loop |
|--------|------------|---------------|
| Sources attempted | 19 | 6 |
| Successful | 16 | 3 |
| Failures (rate-limit/error) | 3 raw errors | 3 (pivoted to alternates) |
| Deferred alternates | — | 2 |
| Wall-clock | 2.01s | 0.32s |
| **Speedup** | — | **6.22x** |
| Unnecessary calls avoided | — | **13** |

Conclusion: the rule-based planner + rate-limit fallback in `src/modules/deep_scan/agent_loop.py` avoids redundant source calls and degrades gracefully when primary sources rate-limit.

---

## 2. Tool Capability Matrix

| Capability | 1ai-osint | Sherlock | Maigret | SpiderFoot | theHarvester | Holehe | Maltego | Recon-ng |
|------------|-----------|----------|---------|------------|--------------|--------|---------|----------|
| **Username enumeration (social platforms)** | ✅ (80+ site checks via username_finder) | ✅ (400+ sites) | ✅ (1000+ sites) | ✅ (as module) | ❌ | ❌ | ✅ (transforms, commercial) | ❌ |
| **Breach data aggregation** | ✅ (HIBP + 5 commercial/aggregator backends, severity-scored, dedup, correlation) | ❌ | ❌ | ✅ (partial, passive) | ❌ | ❌ | ✅ (HIBP transform, commercial) | ❌ |
| **Email→account discovery** | ✅ | ❌ | ❌ | ✅ (partial) | ✅ (email hunter) | ✅ (email only) | ✅ (email entity + transforms) | ❌ |
| **Phone lookup with carrier/format handling** | ✅ (E.164 normalization, ID country-code fallback) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (phone entity; commercial transforms) | ❌ |
| **Secrets / credential scanning** | ✅ (gitleaks-based module, integrated with dossier output) | ❌ | ❌ | ✅ (some modules) | ❌ | ❌ | ❌ | ❌ |
| **Crypto forensics (wallet balances, BIP-39 mnemonics, private-key/passphrase checks)** | ✅ (ZKIT module, 181.7 derivations/sec) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Identity graph correlation (link across sources)** | ✅ (in-memory graph, connected components, cluster scoring) | ❌ | ❌ | ✅ (graph view) | ❌ | ❌ | ✅ (core strength — visual link analysis of entities) | ❌ |
| **AI orchestration (LLM summarization, planner)** | ✅ (LangGraph agent loop, provider-agnostic) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Indonesian-specific sources (PDDIKTI, data.go.id, Pandi WHOIS, NIK)** | ✅ (built-in modules) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ZKIT-specific: crypto + identity + breach correlation** | ✅ (unique differentiator) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Scans one target per invocation** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Standalone CLI + Web UI + REST API** | ✅ CLI/UI/API (auth fail-closed optional) | ✅ CLI | ✅ CLI | ✅ CLI/UI | ✅ CLI | ✅ CLI | ✅ Desktop GUI | ✅ CLI (console) |
| **API key requirements** | Optional (free sources work without keys) | None | None | Some modules | Some | None | Required for most commercial transforms (free CE tier) | Some modules |
| **Language/ecosystem** | Python, async/await, Pydantic models | Python | Python | Python | Python | Python | Java (JVM desktop) | Python |

---

## 3. Where each tool leads

- **Sherlock / Maigret** — broader username site coverage (hundreds to 1000+ sites). 1ai-osint's username_finder is smaller but integrates results into the identity graph and dossier output, and its results flow into the AI correlation step.
- **SpiderFoot** — 200+ passive sources and long-running correlation scans; mature attack-surface recon. 1ai-osint focuses on *person* intelligence (identity, breach, crypto) rather than infrastructure recon.
- **theHarvester** — subdomain/email harvesting for domains, well-suited to infrastructure mapping.
- **Holehe** — simple, focused email→site-signup checker with a large site list.
- **Maltego** — commercial visual link-analysis: its graph/entity model and transform marketplace (DNS, WHOIS, social, HIBP, Shodan) are the industry standard for exploratory link discovery. A free Community Edition exists, but the most powerful transforms require commercial data-provider licenses.
- **Recon-ng** — open-source (MIT) modular recon framework with a Metasploit-style console and 100+ modules; strong for domain/host infrastructure recon and API-driven sources (Shodan, VirusTotal), with no person/identity or crypto focus.

## 4. Where 1ai-osint leads

1. **Breach aggregation with severity scoring** — not just "was this email leaked" but structured, severity-ranked findings with dedup and confidence.
2. **Crypto forensics (ZKIT)** — no mainstream OSINT framework ships mnemonic derivation, balance checking, or private-key/passphrase analysis.
3. **Identity graph correlation** — links a single person's attributes across breach, social, crypto, and phone sources into one dossier (in-memory graph; 15k nodes in ~0.37s, 60 MB).
4. **AI agent loop** — planner picks relevant sources, rate-limit fallback avoids wasted calls (6.22x wall-clock win in the deterministic benchmark), and LLM summary produces an analyst-ready report.
5. **Auth fail-closed option** — setting `REQUIRE_AUTH_TOKENS` (with `WEB_AUTH_TOKEN` / `API_AUTH_TOKEN`) returns 401 for unauthenticated API access (verified live); the local-dev default is intentionally fail-open for zero-config startup (see `docs/evidence/edge-case-matrix.md` §4, `docs/configuration.md` auth section, and `.env.example`, which ships `REQUIRE_AUTH_TOKENS` empty).
6. **Phone/ID normalization** — E.164 + Indonesian ID country-code fallback handling.
7. **Secret scanning as a first-class module** — `src/modules/gitleaks` produces findings that flow into the same severity-scored, deduped dossier pipeline as breach and identity results, rather than a standalone side tool.

## 5. Accuracy, verification & safety (this repo, deterministic)

- **Test suite:** 2462 tests passing, 8 skipped (`uv run pytest`); `ruff check src/ tests/ scripts/` clean; `mypy src/` clean across 301 source files; bandit report on file (`docs/evidence/security/bandit_2026-08-01.json`).
- **Anti-fabrication:** every outbound source call passes a persisted token-bucket rate limiter; findings carry source + timestamp metadata; aggregator backends with no wired vendor adapter are reported *honestly empty*, never synthesized (see `docs/VERIFIED.md`).
- **Safety controls:** SSRF guard on `deep_scraper` and `domain_recon` (blocks private/internal targets), XSS-escaping in HTML/JSON exports, optional fail-closed auth, per-client inbound throttling via `RequestLimiter`.
- **Soak evidence:** rate-limiter + cache stability run — `docs/evidence/soak/receipt_2026-08-01.json`.
- **Recorded, not hidden:** a prior benchmark receipt (`docs/evidence/benchmark/receipt_2026-08-01.json`) failed on real API errors (79 api_errors, 32.6% error rate) and is kept as evidence; the single open dependency advisory (`ecdsa` 0.19.2, PYSEC-2026-1325, no upstream fix) is transitive and recorded in the CVE scan files.

## 6. Honest caveats (not certifiable offline)

- Live source freshness, uptime, and regional availability vary; no offline run can certify real-world breadth.
- Sherlock/Maigret site-count advantages are real for username-only hunts.
- Maltego/Recon-ng rows are assessed from public documentation; Maltego's commercial transform breadth is licensed, not replicated here.
- Breach backend coverage depends on the operator's own API keys for commercial aggregators.
- "Best in the world" is a marketing claim; this matrix documents measured and structural strengths, not an absolute industry ranking. Independent third-party audit is the remaining step before any such claim could be made responsibly.
