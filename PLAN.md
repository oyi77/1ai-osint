# Plan: 1ai-osint — AI-Powered OSINT & ZKIT Research Platform

## TL;DR

> **1ai-osint** is a unified, CLI-first OSINT platform that extends your existing HellCatZ codebase with AI-powered intelligence, crypto leak detection, and a novel **Zero Knowledge Identity Tracking (ZKIT)** protocol. The project produces both a usable tool and an academic paper suitable for journals/conferences + Zenodo preprint.

> **Key innovations**: (1) Hash-based ZKIT protocol for privacy-preserving identity correlation, (2) LangGraph + Omniroute AI orchestration for smart OSINT workflow automation, (3) Integrated crypto leak detection pipeline.

---

## Context

### Current State (HellCatZ)
Your existing project `DIRJEN-BOT/hellcatz` already provides:
- **CLI-first architecture** with `OSINTTool` base class
- **19+ provider integrations** (Sherlock, Maigret, Holehe, h8mail, PhoneInfoga, Amass, etc.)
- **Modular design** with parallel executor, caching, rate limiting
- **Feedback system** for false positive/negative learning
- **FastAPI REST API** layer
- **Docker support**

### What's Missing for 1ai-osint
- AI-driven orchestration (LangGraph + Omniroute)
- Crypto-specific modules (passphrase generation, leak detection, key checker)
- ZKIT identity correlation engine
- Gitleaks/TruffleHog integration for repo secret scanning
- Graph-based entity linking and risk scoring
- Research paper framework

### Omniroute Role
Omniroute (`diegosouzapw/OmniRoute`) serves as the **unified AI gateway**:
- Single endpoint to 160+ LLM providers
- Smart auto-fallback when providers fail
- RTK+Caveman compression (~95% context savings)
- MCP/A2A protocol support
- Multimodal API access

This replaces direct OpenAI API calls → gives you provider flexibility, cost optimization, and resilience.

---

## Existing Libraries to Reuse

### Crypto Modules (DO NOT REINVENT — Use Battle-Tested Libraries)

| Feature | Recommended Library | Alternative | License | Notes |
|---------|---------------------|-------------|---------|-------|
| BIP-39 mnemonic generation | `bip-utils` | `mnemonic` (Trezor) | MIT | Supports 50+ cryptos, BIP-32/38/85 |
| Seed phrase validation | `bip-utils` or `bip39lib` | `mnemonic` | MIT | Checksum validation |
| Ethereum key management | `eth-account` or `web3.py` | — | MIT | Official Ethereum libs |
| Bitcoin key parsing | `bip-utils` | `bitcoinlib` | MIT | Avoid fake `bitcoinlibdbfix` |
| Solana keys | `solders` | `solana` | MIT | Fast, lightweight |
| Private key detection | `trufflehog` (verification) | `BTCKeySearch` | AGPL-3.0 | 800+ secret types, live verification |
| Secret/API key scanning | **GitHound** (user chose) | `secret_detector` | MIT | GitHub-wide, entropy+context detection |
| Seed phrase scanner | `seed-sweep` | `BTCKeySearch` | MIT | BIP-39 + wallet file detection |

### OSINT Modules (Reuse from HellCatZ)

| Feature | Existing HellCatZ Module | Status |
|---------|--------------------------|--------|
| People Finder | `sherlock`, `maigret`, `whatsmyname` | Already working |
| Phone Finder | `phoneinfoga` | Already working |
| Breach Aggregation | `leak_aggregator` + 10 providers | Already working |
| Domain/OSINT | `amass`, `theharvester`, `spiderfoot` | Already working |

### AI/Orchestration (User-Specified)

| Feature | Library | License |
|---------|---------|---------|
| AI gateway | Omniroute (diegosouzapw/OmniRoute) | — |
| Workflow orchestration | LangGraph | MIT |
| LLM providers | Via Omniroute (160+ options) | Various |

### Testing & Utilities

| Feature | Library | Notes |
|---------|---------|-------|
| Testing | `pytest` + `pytest-cov` | 80%+ coverage target |
| CLI | `typer` or `click` | Match HellCatZ pattern |
| Data models | `pydantic` | Already in HellCatZ |
| HTTP client | `httpx` | Async, already in HellCatZ |
| Caching | File-based (JSON) | Already in HellCatZ |

---

## Work Objectives

### Core Objective
Build a research-grade OSINT platform with novel ZKIT protocol, demonstrated through both working software and published academic work.

### Concrete Deliverables
1. **1ai-osint CLI tool** — pip-installable Python package
2. **ZKIT protocol specification** — formal definition document
3. **AI orchestration layer** — LangGraph workflows using Omniroute
4. **9 functional modules** (see Module Specs below)
5. **Academic paper** — submitted to IEEE Access / Computers & Security + Zenodo preprint
6. **Full test suite** — 80%+ coverage, TDD methodology
7. **Docker deployment** — single-command setup

### MVP Scope (Must Have vs Nice to Have)

**MVP (Weeks 1-12) — Core Research Deliverables:**
- OSINTTool base class extension
- TDD framework with 80% coverage
- Omniroute AI gateway integration
- Gitleaks module (secret scanning)
- Data Leaks aggregator (extend existing HellCatZ)
- ZKIT Identity Tracker (lightweight hash protocol)
- Crypto Passphrase Checker (entropy + dictionary)
- AI Entity Extractor (LangGraph orchestration)
- ZKIT Protocol documentation
- Research paper abstract + intro + methods

**Post-MVP (Weeks 13-18) — Enhanced Features:**
- People Finder (social media aggregation)
- Phone Finder (carrier + linked accounts)
- Crypto Passphrase Randomizer (BIP-39 generation)
- Crypto Private Key Scanner + Checker
- Risk Scorer (ML-based anomaly detection)
- Full report generator (JSON + SARIF + PDF)
- Zenodo preprint publication

### Definition of Done
- [ ] All 9 modules implemented with tests
- [ ] LangGraph + Omniroute orchestration working end-to-end
- [ ] ZKIT protocol documented and implemented
- [ ] Paper draft complete with experimental results
- [ ] Zenodo preprint published with DOI
- [ ] Test coverage >= 80%

---

## Verification Strategy

### Test Framework
- **pytest** with pytest-cov for coverage
- **TDD approach**: Red -> Green -> Refactor for every module
- **Agent-executed QA scenarios** for each module
- **Integration tests** using mock API responses

### Module-Level Verification
Each module verified through:
1. Unit tests for core logic
2. Integration tests for API integrations
3. End-to-end test with sample data
4. Performance benchmarks

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Foundation — Weeks 1-3)
├── Task 1: Project scaffolding & HellCatZ fork/branch
├── Task 2: Base class extension (OSINTTool v2 with ZKIT support)
├── Task 3: TDD framework setup (pytest, fixtures, coverage)
├── Task 4: Omniroute integration layer
├── Task 5: Docker & CI/CD configuration
├── Task 6: Gitleaks integration module
└── Task 7: Data leaks aggregation module (extend existing)

Wave 2 (Core Modules — Weeks 4-7)
├── Task 8: People Finder module (reuse Sherlock/Maigret/WhatsMyName)
├── Task 9: Phone Finder module (reuse PhoneInfoga)
├── Task 10: Crypto Passphrase Randomizer & Checker
├── Task 11: Crypto Private Key Scanner & Checker
├── Task 12: AI Entity Extractor (LangGraph + Omniroute)
├── Task 13: Risk Scorer module
└── Task 14: Output/Report Generator (JSON/SARIF/PDF)

Wave 3 (ZKIT Engine — Weeks 8-10)
├── Task 15: Identity Graph Builder (hash-based correlation)
├── Task 16: ZKIT Protocol Implementation (lightweight)
├── Task 17: Cross-Module Correlation Engine
├── Task 18: Privacy-Preserving Report Generator
└── Task 19: ZKIT Documentation & Protocol Paper

Wave 4 (Research & Polish — Weeks 11-14)
├── Task 20: Experimental Design & Benchmarking
├── Task 21: Paper Draft (Methods + Results)
├── Task 22: Paper Draft (Intro + Related Work + Discussion)
├── Task 23: Zenodo Preprint Preparation
└── Task 24: Final Integration & Demo

Wave 5 (Verification — Week 15)
├── Task F1: Plan Compliance Audit
├── Task F2: Code Quality Review
├── Task F3: Full Integration Testing
└── Task F4: Paper Final Review
```

### Dependency Matrix (Revised — Critical Path Unblocked)

| Task | Blocks | Blocked By |
|------|--------|------------|
| 1 (Scaffolding) | 2, 3, 5 | None |
| 2 (Base classes) | 8, 9, 12, 13, 15 | 1 |
| 3 (TDD framework) | 6, 7, 8, 9, 10, 11 | 1 |
| 4 (Omniroute) | 12, 13 | None |
| 5 (Docker/CI) | 24 | 1 |
| 6 (Gitleaks) | 14, 17 | 2, 3 |
| 7 (Data Leaks) | 14, 17 | 2, 3 |
| 8 (People Finder) | 14, 17 | 2, 3 |
| 9 (Phone Finder) | 14, 17 | 2, 3 |
| 10 (Crypto Passphrase) | 14, 17 | 2, 3, 4 |
| 11 (Crypto Private Key) | 14, 17 | 2, 3, 4 |
| 12 (AI Entity Extractor) | 13, 17 | 2, 4 |
| 13 (Risk Scorer) | 14, 17 | 2, 12 |
| 14 (Report Generator) | 18, 22 | 2, 6, 7, 8, 9, 10, 11, 12, 13 |
| 15 (Identity Graph) | 16, 17 | 2 |
| 16 (ZKIT Protocol) | 17, 18, 19 | 15 |
| 17 (Correlation Engine) | 20, 22 | 15, 16, 14 |
| 18 (Privacy Reports) | 22 | 16 |
| 19 (ZKIT Docs) | 21 | 16 |
| 20 (Benchmarks) | 21, 22 | 17 |
| 21 (Paper Methods+Results) | 22 | 20 |
| 22 (Paper Intro+Discussion) | 23 | 21 |
| 23 (Zenodo) | 24 | 22 |
| 24 (Integration) | F1-F4 | 5, 23 |

### Key Change
**Task 17 (Correlation Engine)** now depends only on:
- Task 15 (Identity Graph) — the ZKIT graph structure
- Task 16 (ZKIT Protocol) — the correlation rules
- Task 14 (Report Generator) — needs aggregated data

**No longer blocked by**: Individual modules (6-13). These feed into Task 14, which then feeds into 17. This breaks the critical path bottleneck and allows parallel module development.

---

## Module Specifications

### Module 1: Gitleaks Integration
- **Purpose**: Scan git repositories for leaked secrets (API keys, tokens, credentials)
- **Reuse**: HellCatZ OSINTTool pattern + **GitHound** (user chose)
- **GitHound features**: GitHub Code Search API, regex + entropy + context matching, contextual false positive filtering
- **Input**: GitHub query, repo URL, or local path
- **Output**: JSON with findings (file, line, secret type, severity, confidence score)
- **AI Layer**: LangGraph node for false positive filtering using Omniroute LLM
- **TDD**: Test detection accuracy against known leaked repos

### Module 2: Data Leaks Aggregator
- **Purpose**: Aggregate breach data from multiple sources
- **Reuse**: HellCatZ LeakAggregatorTool (extend with new sources)
- **Input**: Email, username, domain
- **Output**: Deduplicated breach records with severity scores
- **AI Layer**: Entity extraction + correlation across breach sources
- **TDD**: Test deduplication, error handling, API failures

### Module 3: People Finder
- **Purpose**: Search social media, forums, public databases for person profiles
- **Reuse**: HellCatZ Sherlock/Maigret/WhatsMyName wrappers
- **Input**: Name, email, username, phone number
- **Output**: Profile links with confidence scores
- **AI Layer**: Profile deduplication across platforms, identity merging
- **TDD**: Test search accuracy, rate limiting, output normalization

### Module 4: Phone Finder
- **Purpose**: OSINT on phone numbers (carrier, location, linked accounts)
- **Reuse**: HellCatZ PhoneInfoga wrapper
- **Input**: Phone number (E.164 format)
- **Output**: Carrier, location, VoIP status, linked social accounts
- **AI Layer**: Anomaly detection (VOIP vs real, number reuse patterns)
- **TDD**: Test format validation, API integration, error handling

### Module 5: Identity Tracker (ZKIT)
- **Purpose**: Correlate identities across leaked data without exposing raw PII
- **Protocol**: Lightweight SHA-256 hash-based correlation
- **ZKIT Protocol**:
  1. Input: Raw identity attributes
  2. Hash: SHA-256(salt + attribute) for each attribute
  3. Correlate: Match hashed attributes across data sources
  4. Score: Risk score based on correlation strength and data freshness
  5. Output: Graph with hashed nodes (no raw PII exposed)
- **TDD**: Test hash consistency, correlation accuracy, privacy guarantees

### Module 6: Crypto Passphrase Randomizer & Checker
- **Purpose**: Generate cryptographically secure seed phrases and validate entropy
- **Libraries to Reuse**:
  - `bip-utils` (ebellocchia/bip_utils) — BIP-39/BIP-32/BIP-85, 50+ cryptos, MIT licensed
  - OR `mnemonic` (Trezor reference impl) — simpler, for basic BIP-39 only
  - OR `hdwallet` — rich API with multi-currency support
- **Features**:
  - BIP-39 mnemonic generation (12/15/18/21/24 words)
  - Shannon entropy analysis (Python `math.log2`)
  - Dictionary check against common/weak passphrases (custom wordlist + BIP-39 wordlist)
  - Strength scoring (bits of entropy)
- **Input**: Optional word count, optional custom wordlist
- **Output**: Generated passphrase + entropy score + strength rating
- **TDD**: Test entropy calculations, BIP-39 compliance, edge cases

### Module 7: Crypto Private Key Scanner
- **Purpose**: Detect leaked crypto private keys in code/repos
- **Primary Tool**: **GitHound** (user chose) — GitHub Code Search API, regex + entropy + context matching
- **Additional Tools**: `trufflehog` for verification, `seed-sweep` for BIP-39 seed phrase detection
- **Libraries to Reuse**:
  - `bip-utils` — For validating/detecting private key formats (WIF, hex, etc.)
  - `trufflehog` — For comprehensive secret verification
- **Detection Coverage**:
  - Bitcoin (WIF compressed/uncompressed, hex, mini private key, BIP-32 xpriv)
  - Ethereum (hex private key, mnemonic seed)
  - Solana (Base58)
  - General ECDSA/Ed25519 keys (PEM, OPENSSH formats)
  - BIP-39 seed phrases (12/15/18/21/24 words)
- **Input**: File path, git URL, GitHub query
- **Output**: Detected keys with format, chain, and risk level
- **AI Layer**: Context analysis (is this a test key? example in docs? real leak?)
- **TDD**: Test against known key formats, false positive filtering

### Module 8: AI Orchestrator (LangGraph + Omniroute)
- **Purpose**: Coordinate all modules through intelligent workflow
- **Features**: Dynamic workflow routing, parallel execution, LLM analysis, error recovery
- **TDD**: Test workflow routing, error handling, result aggregation

### Module 9: Report Generator
- **Purpose**: Produce structured, privacy-preserving reports
- **Formats**: JSON, SARIF (GitHub Security tab), PDF, HTML
- **Features**: Severity classification, ZKIT-compatible output, remediation recommendations, confidence scores
- **TDD**: Test format correctness, data sanitization, output completeness

---

## ZKIT Protocol Specification (Lightweight)

### Overview
Zero Knowledge Identity Tracking enables correlation of identities across data sources without exposing raw personal information.

### Protocol Steps
1. **Ingestion**: Raw data enters the system (leaked emails, usernames, phones)
2. **Hashing**: Each attribute is salted and hashed: `H(salt || attribute)`
3. **Graph Construction**: Hashed attributes become nodes; co-occurrence creates edges
4. **Correlation**: Matching hash nodes across sources link identities
5. **Scoring**: Risk score based on number of correlated sources, data freshness, attribute diversity
6. **Output**: Graph with hashed nodes only — raw PII never exposed in reports

### Privacy Guarantees
- Raw PII exists only in memory during processing
- All persistent storage uses hashed identifiers
- Optional: client-side hashing for maximum privacy
- No reversible encryption of identity attributes

### Research Contribution
This protocol enables:
- Cross-platform identity correlation for investigations
- Privacy-preserving data sharing between organizations
- Compliance with GDPR/privacy regulations while maintaining investigative capability

---

## AI Integration Architecture

### Omniroute as LLM Gateway
```
LangGraph Node -> Omniroute SDK -> [Provider: OpenAI/Gemini/Claude/etc.] -> Response
                                   ↓
                           Auto-failover
                           Context compression
                           Usage optimization
```

### AI Use Cases
1. **Entity Extraction**: LLM extracts structured data from unstructured OSINT results
2. **False Positive Filtering**: AI evaluates whether a detected "secret" is real
3. **Correlation Reasoning**: AI identifies non-obvious connections between entities
4. **Report Generation**: Natural language summaries of findings
5. **Investigation Suggestions**: AI recommends next investigation steps

---

## Testing Strategy

### TDD Approach
```
For each module:
1. Write failing tests (RED)
2. Implement minimal code (GREEN)
3. Refactor and optimize (REFACTOR)
4. Document in SDD
```

### Test Categories
| Category | Priority | Coverage Target | Notes |
|----------|----------|-----------------|-------|
| Unit tests (core logic) | P0 | **90%+** | ZKIT hash, entropy calc, key validation |
| Integration tests (APIs) | P1 | **80%+** | Gitleaks, data leaks, providers |
| Edge case tests | P2 | **70%+** | Malformed inputs, rate limits |
| Performance tests | P3 | Baseline benchmarks | Scan speed < 5s for 1000 files |
| Regression tests | P1 | All known bugs | Zero tolerance |

### Performance Benchmarks
| Metric | Target |
|--------|--------|
| Secret scan (1000 files) | < 5 seconds |
| ZKIT graph construction (1000 identities) | < 2 seconds |
| Full workflow (email → all modules) | < 60 seconds |
| Memory usage (idle) | < 200MB |
| Docker image size | < 500MB |

### Test Data Strategy
- Synthetic test data (no real PII)
- Known public breach datasets (for validation only)
- Mock API responses for external services
- Planted test secrets in sandbox repositories

---

## Research Paper Outline

# Zero Knowledge Identity Tracking (ZKIT): Leveraging AI, OSINT, and Leaked Data for Comprehensive Investigations

## Abstract
A novel framework combining OSINT automation, AI-powered analysis, and privacy-preserving identity correlation for comprehensive security investigations.

## 1. Introduction
- Motivation: Growing complexity of OSINT investigations
- Problem: Current tools lack AI reasoning and privacy preservation
- Contributions: ZKIT protocol, integrated tool, experimental validation

## 2. Background & Related Work
- OSINT tool landscape (Gitleaks, TruffleHog, Sherlock, etc.)
- Zero Knowledge Proofs in identity verification
- AI applications in cybersecurity
- Gap analysis: lack of integrated, privacy-preserving OSINT platforms

## 3. ZKIT Framework
- 3.1 Conceptual Model
- 3.2 Protocol Specification
- 3.3 Architecture Design
- 3.4 Privacy Analysis

## 4. Implementation: 1ai-osint
- 4.1 System Architecture
- 4.2 Module Specifications
- 4.3 AI Orchestration Layer
- 4.4 Integration with Omniroute

## 5. Experimental Evaluation
- 5.1 Test Setup & Datasets
- 5.2 Detection Accuracy (precision/recall/F1)
- 5.3 AI Enhancement Impact (with vs without AI)
- 5.4 Performance Benchmarks
- 5.5 Privacy Guarantees Verification

## 6. Discussion
- 6.1 Ethical Considerations
- 6.2 Limitations
- 6.3 Comparison with Existing Tools
- 6.4 Future Work

## 7. Conclusion

## References

---

## Project Structure

```
1ai-osint/
├── README.md                       # Project overview & quick start
├── CONTRIBUTING.md                 # Contribution guidelines
├── LICENSE                         # MIT License
├── pyproject.toml                  # Python project configuration
├── requirements.txt                # Dependencies
│   # Core
│   # - typer>=0.12.0
│   # - pydantic>=2.0
│   # - httpx>=0.25
│   #
│   # AI / Orchestration
│   # - langgraph>=0.1.0
│   # - omniroute (via git+https)
│   #
│   # Crypto (bip-utils covers most needs)
│   # - bip-utils>=2.10.0  # BIP-39/32/38/85 for 50+ cryptos
│   # OR
│   # - mnemonic>=0.21     # Trezor reference, simpler
│   #
│   # Secret Scanning
│   # - githound (via git+https)   # User chose GitHound
│   # - trufflehog>=3.0   # For verification, 800+ secret types
│   #
│   # Testing
│   # - pytest>=8.0
│   # - pytest-cov>=4.0
├── Dockerfile                      # Container configuration
├── docker-compose.yml              # Multi-service setup
├── .github/
│   └── workflows/
│       └── ci.yml                  # CI/CD pipeline
├── docs/
│   ├── SDD.md                      # Software Design Document
│   ├── ZKIT_PROTOCOL.md            # ZKIT protocol specification
│   ├── RESEARCH_PAPER.md           # Paper draft
│   ├── API_REFERENCE.md            # API documentation
│   └── CONTRIBUTING.md
├── src/
│   ├── cli.py                      # Main CLI entrypoint (typer)
│   ├── config.py                   # Configuration management
│   ├── models.py                   # Pydantic data models
│   ├── database.py                 # SQLite storage layer
│   ├── cache.py                    # Caching utilities
│   └── rate_limiter.py             # Rate limiting
├── src/modules/
│   ├── gitleaks/
│   │   ├── scanner.py
│   │   ├── parser.py
│   │   └── tests/
│   ├── data_leaks/
│   │   ├── aggregator.py
│   │   ├── breach_checker.py
│   │   └── tests/
│   ├── people_finder/
│   │   ├── search.py
│   │   └── tests/
│   ├── phone_finder/
│   │   ├── lookup.py
│   │   └── tests/
│   ├── crypto/
│   │   ├── passphrase_generator.py
│   │   ├── passphrase_checker.py
│   │   ├── privatekey_scanner.py
│   │   └── tests/
│   ├── identity_tracking/
│   │   ├── zkit_engine.py
│   │   ├── identity_graph.py
│   │   └── tests/
│   └── output/
│       ├── report_generator.py
│       ├── json_formatter.py
│       ├── sarif_formatter.py
│       ├── pdf_generator.py
│       └── tests/
├── src/ai/
│   ├── orchestrator.py             # LangGraph workflow engine
│   ├── analyzers/
│   │   ├── entity_extractor.py
│   │   ├── risk_scorer.py
│   │   └── correlation_engine.py
│   ├── models/
│   │   ├── prompts.py
│   │   └── schemas.py
│   └── omniroute_client.py         # Omniroute API integration
├── tests/
│   ├── unit/
│   │   ├── test_crypto.py
│   │   ├── test_zkit.py
│   │   ├── test_entities.py
│   │   └── test_reports.py
│   ├── integration/
│   │   ├── test_orchestrator.py
│   │   ├── test_gitleaks.py
│   │   └── test_full_workflow.py
│   └── fixtures/
│       ├── sample_secrets.json
│       ├── test_identities.json
│       └── mock_api_responses.py
└── notebooks/
    ├── zkit_analysis.ipynb
    └── experimental_results.ipynb
```

---

## Timeline (18 Weeks — with buffer for research paper)

| Week | Tasks | Deliverable |
|------|-------|-------------|
| 1-2 | Scaffolding, base classes, TDD setup | Repo structure, first tests passing |
| 3 | Omniroute integration, Docker setup | AI gateway working, container builds |
| 4-5 | Gitleaks + Data Leaks modules | Secret scanning functional |
| 6-7 | People Finder + Phone Finder | OSINT aggregation working |
| 8-9 | Crypto modules (passphrase + key scanner) | Crypto detection functional |
| 10-11 | ZKIT engine + Identity Graph | Privacy layer working |
| 12-13 | AI Orchestrator + Report Generator | End-to-end workflow, all outputs |
| 14-16 | **Paper Writing** (Iterative drafting starts Week 10) | Full paper draft with experimental results |
| 17 | Zenodo Preprint Preparation | DOI published |
| 18 | Final Integration + Review + Buffer | Final polish, integration tests pass |

### Buffer Strategy
- **3 extra weeks** added (15 → 18 weeks) to absorb delays
- Paper drafting starts **Week 10** (iterative, not sequential)
- Integration testing happens in parallel with paper finalization

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Omniroute API changes | Abstract behind client class, easy to swap |
| LLM costs too high | Local Llama fallback, caching |
| ZKIT too complex for paper | Start lightweight, document formally |
| HellCatZ compatibility issues | Fork and extend, don't modify original |
| Test coverage gaps | Enforce CI gate at 80% |

---

## Success Criteria

- [ ] All 9 modules implemented with tests
- [ ] LangGraph + Omniroute orchestration functional
- [ ] ZKIT protocol documented and implemented
- [ ] Paper draft complete with experimental results
- [ ] Zenodo preprint with DOI published
- [ ] **Overall test coverage >= 80%** (enforced by CI gate)
- [ ] **ZKIT core modules (15, 16) coverage >= 90%**
- [ ] **AI modules (12, 13) coverage >= 80%**
- [ ] **Crypto modules (10, 11) coverage >= 85%**
- [ ] Docker deployment working
- [ ] No raw PII in any persistent output
- [ ] All performance benchmarks met (see table above)

---

## Next Steps

1. **Create the full work plan** at `.sisyphus/plans/1ai-osint.md`
2. **Start with Module Specifications** — define exact interfaces before coding
3. **Set up TDD framework** — first failing tests
4. **Document ZKIT protocol** — formal specification document

Shall I proceed with creating the full work plan and starting Phase 1?