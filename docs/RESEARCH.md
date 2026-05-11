# Draft: 1ai-osint Research Project

## Requirements (confirmed)
- **Name**: 1ai-osint — one-stop all-in-one OSINT tool
- **Core philosophy**: Research-first → full SDD & TDD BEFORE any code
- **Target audience**: Security researchers, red-teamers, academic publication

## Modules Required
- people_finder: Social media username search (reuse HellCatZ Sherlock/Maigret/WhatsMyName)
- phone_finder: Phone number OSINT (reuse HellCatZ PhoneInfoga)
- identity_tracking: ZKIT engine — Zero Knowledge Identity Tracking
- gitleaks: Secret scanning in repos (integrate gitleaks/trufflehog)
- data_leaks: Breach/leak aggregation (reuse HellCatZ leak_aggregator)
- crypto_passphrase_randomizer: Generate & validate crypto seed phrases
- crypto_passphrase_checker: Entropy + dictionary validation
- crypto_privatekey_leaks: Detect leaked private keys in code/repos
- crypto_privatekey_checker: Validate/flag exposed keys

## Technical Decisions (Final)
- **AI orchestration**: LangGraph (Python-native, graph-based, proven for complex workflows)
- **AI gateway**: Omniroute (160+ providers, auto-fallback, compression) — user choice
- **CLI framework**: Python typer/click (matches HellCatZ pattern)
- **Base class reuse**: Extend HellCatZ OSINTTool interface
- **ZKIT concept**: Lightweight SHA-256 hash-based correlation (user chose lightweight)
- **Testing**: TDD with pytest, 80%+ coverage overall, 90%+ for ZKIT core
- **Output**: SARIF + JSON + PDF/HTML reports

## Libraries to Reuse (NO REINVENTING)
- **BIP-39 crypto**: `bip-utils` (MIT, supports 50+ cryptos, BIP-32/38/85)
- **Ethereum**: `eth-account` or `web3.py` (official libs)
- **Bitcoin**: `bip-utils` (not bitcoinlib — beware fake PyPI packages)
- **Private key detection**: `trufflehog` (AGPL, proven at scale)
- **Seed phrase scanning**: `seed-sweep` (BIP-39 + wallet files)
- **Secret detection**: `secret_detector` (100+ regex patterns, MIT)
- **OSINT providers**: HellCatZ existing (Sherlock, Maigret, PhoneInfoga, etc.)

## HellCatZ Reuse Strategy
- Reuse: OSINTTool base class, CLI structure, caching, rate limiting, feedback system
- Reuse: Provider wrappers (sherlock, maigret, holehe, phoneinfoga, h8mail, etc.)
- Reuse: LeakAggregator parallel execution pattern
- Extend: Add AI orchestration layer (LangGraph), ZKIT engine, crypto modules
- Extend: Add graph-based entity correlation, privacy-preserving output

## Paper Target
- Academic journal: IEEE Access / Computers & Security
- Preprint: Zenodo (with DOI)
- Timeline: Iterative drafting starts Week 10, publication by Week 17-18

## Timeline (Revised)
- 18 weeks total (with 3-week buffer for paper writing)
- MVP scope: Weeks 1-12 (core research deliverables)
- Post-MVP: Weeks 13-18 (enhanced features + publication)

## Momus Review Feedback (Addressed)
1. ✅ Timeline expanded 15 → 18 weeks with buffer
2. ✅ Task 17 dependency bottleneck fixed (now depends on ZKIT modules + Report Generator only)
3. ✅ MVP scope markers added (must-have vs nice-to-have)
4. ✅ Coverage targets clarified per module type
5. ✅ Performance benchmarks added with specific targets
6. ✅ Added "Libraries to Reuse" section — no wheel reinvention

## Open Questions (Resolved)
- Q: Exact ZKIT protocol? → **Lightweight (SHA-256 hash)**
- Q: Which LLM? → **Omniroute (160+ providers, user choice)**
- Q: Paper venue? → **IEEE Access + Zenodo preprint**

## Status: ✅ PLAN FINALIZED — Awaiting User Approval