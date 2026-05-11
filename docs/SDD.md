# Software Design Document — 1ai-osint

## 1. Introduction
- **Purpose**: Unified CLI/AI OSINT platform with privacy-preserving identity tracking
- **Scope**: 9 modules spanning secret scanning, OSINT aggregation, crypto analysis, ZKIT
- **Research Contribution**: ZKIT protocol for GDPR-compliant identity correlation

## 2. System Architecture
```
User → CLI → LangGraph Orchestrator (AI) → Module Workers → ZKIT Engine → Report
                              ↕
                    Omniroute (LLM gateway)
```

## 3. Module Specifications
See `PLAN.md` for full module specs per section.

## 4. Data Flow
1. CLI receives target/query
2. LangGraph routes to appropriate modules
3. Modules run in parallel where possible
4. Results fed to ZKIT engine for identity correlation
5. AI layer filters false positives, enriches findings
6. Report generated in requested format

## 5. ZKIT Protocol (Lightweight)
```
Attributes → SHA-256(salt || attr) → Identity Graph → Correlation → Risk Score
```
No raw PII stored. See `docs/RESEARCH.md` for full protocol specification.

## 6. Testing
- TDD methodology: RED → GREEN → REFACTOR
- Target: 80%+ coverage, 90%+ for ZKIT core
- See `PLAN.md` for test categories and benchmarks

## 7. Deployment
- Docker: `docker build -t 1ai-osint . && docker run -it 1ai-osint`
- Pip: `pip install .`
- Dev: `python -m src.cli`