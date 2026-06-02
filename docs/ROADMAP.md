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

## Phase 0 — Reliable core (weeks 0–6) `IN PROGRESS`

- [x] `sherlock-project` core dependency
- [x] Deep scan fast profile + dedupe + name pivots
- [x] Operational briefing HTML/JSON (`briefing.*`)
- [ ] `1ai-osint doctor` — environment health
- [ ] `deep-scan --profile fast|standard|deep|agency`
- [ ] Breach router (keyed APIs only)
- [ ] Golden integration test (mocked, no live PII in CI)
- [ ] PDF from briefing template

## Phase 1 — Agency packet depth (weeks 6–14)

- [ ] Email OSINT + Holehe in standard/agency profiles
- [ ] Phone finder + E.164 normalization
- [ ] Breach normalizer → INTEL_STANDARD field taxonomy
- [ ] Indonesia pack: NIK parser, locale phones
- [ ] AI: BLUF + judgments (cited to evidence IDs only)
- [ ] STIX 2.1 bundle validation in CI
- [ ] `investigations/<case_id>/` case folders

## Phase 2 — Differentiation (weeks 14–26)

- [ ] ZKIT graph export (Neo4j JSON)
- [ ] LangGraph planner: budget-aware module scheduling
- [ ] Monitor mode + delta briefings
- [ ] Crypto wallet → same briefing packet
- [ ] Plugin SDK + module discovery registry

## Phase 3 — Ecosystem (weeks 26–40)

- [ ] FastAPI async jobs + report API
- [ ] Report viewer UI
- [ ] Distributed node collection (`src/modules/node`)
- [ ] Public benchmark + reproducibility package
- [ ] Research paper + Zenodo

---

## Architecture

```
CLI → profile resolver → DeepScanEngine → [modules + breach router]
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

## Immediate backlog (30 days)

1. `doctor` command
2. Scan profiles `standard` / `deep` / `agency`
3. Breach router wired to engine
4. Deprecate duplicate PeopleFinderTool subprocess path
5. README analyst quickstart + API key table
6. Do not commit scan artifacts or `.session` files
