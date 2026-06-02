# 1ai-osint Roadmap — Best OSINT Platform

North star: **any seed identifier → agency-structured operational packet** with ZKIT correlation,
full provenance, and incremental collection until gaps are explicit.

See also: [INTEL_STANDARD.md](./INTEL_STANDARD.md) for briefing section requirements.

---

## Vision tiers

| Tier | Definition | Horizon |
|------|------------|---------|
| T1 | Best open-source CLI OSINT | Phase 0–1 |
| T2 | Best OSINT + crypto leak vertical | Phase 2 |
| T3 | Approaches commercial leak intel depth (with API keys) | Phase 1–2 |
| T4 | Agency-*structured* packet (not classified data) | Phase 1+ |

---

## Phase 0 — Reliable core `DONE`

- [x] `sherlock-project` core dependency
- [x] Deep scan fast profile + dedupe + name pivots
- [x] Operational briefing HTML/JSON (`briefing.*`)
- [x] `1ai-osint doctor` — environment health
- [x] `deep-scan --profile fast|standard|deep|agency`
- [x] Breach router (keyed APIs only)
- [x] Golden integration test (mocked, no live PII in CI)
- [x] PDF from briefing template

## Phase 1 — Agency packet depth `MOSTLY DONE`

- [x] Email OSINT + Holehe in standard/agency profiles
- [x] Phone finder + E.164 normalization
- [x] Breach normalizer → INTEL_STANDARD field taxonomy
- [ ] Indonesia pack: NIK parser, locale phones (partial via NIK type + ID default)
- [x] AI: BLUF + judgments (`--ai`, evidence-cited)
- [x] STIX 2.1 bundle + CI shape validation
- [x] `investigations/<case_id>/` case folders + delta on re-run

## Phase 2 — Differentiation `IN PROGRESS`

- [x] ZKIT graph export (Neo4j JSON in intel JSON)
- [ ] LangGraph planner: budget-aware module scheduling
- [x] Monitor delta briefings (`delta_briefing` + `--case`)
- [ ] Crypto wallet → same briefing packet (crypto modules exist; briefing merge pending)
- [x] Module discovery registry (`module_discovery.py`)

## Phase 3 — Ecosystem `STARTED`

- [x] FastAPI async jobs skeleton (`src/api/app.py`)
- [ ] Report viewer UI
- [ ] Distributed node collection (`src/modules/node`)
- [ ] Public benchmark + reproducibility package
- [ ] Research paper + Zenodo

---

## Architecture

```
CLI / API → profile resolver → DeepScanEngine → [modules + breach router]
                              ↓
                         ZKIT correlator
                              ↓
                    briefing_builder + AI (cited)
                              ↓
                    HTML / JSON / STIX / PDF
```

---

## Module priority

**P0:** deep_scan, people_finder, social_osint, breach router, briefing  
**P1:** data_leaks, email_osint, phone_finder, domain_recon  
**P2:** identity_tracking ZKIT export, gitleaks, monitor  
**P3:** vuln_scanner, node network, API layer

---

## KPIs

| Milestone | Metric |
|-----------|--------|
| Phase 0 done | `doctor` green; `--profile fast` &lt;15s p95 on fixture |
| Phase 1 done | Agency profile fills §IV when 2+ breach keys set |
| Phase 2 done | Case diff report; ZKIT clusters on fixture set |

---

## Analyst quickstart

```bash
pip install -e .
cp .env.example .env   # HIBP, DeHashed, LeakCheck, IntelX for §IV
1ai-osint doctor
1ai-osint deep-scan "Target Name" --profile fast
1ai-osint deep-scan target@email.com --profile agency --case INV-001 --pdf --ai
uvicorn src.api.app:app --reload   # POST /v1/scan
```

| Key | Enables |
|-----|---------|
| `HIBP_API_KEY` | Have I Been Pwned |
| `DEHASHED_API_KEY` / email | DeHashed |
| `LEAKCHECK_API_KEY` | LeakCheck |
| `INTELX_API_KEY` | IntelX |
| `OPENAI_API_KEY` or `OMNIROUTE_API_KEY` | `--ai` BLUF enhancement |

Do not commit scan artifacts, `.session`, or investigation outputs.
