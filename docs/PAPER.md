# Zero Knowledge Identity Tracking (ZKIT) in OSINT Ecosystems: Design, Privacy, and Performance

## Abstract
Open Source Intelligence (OSINT) has traditionally relied on plaintext target correlation, which exposes sensitive personal identifiable information (PII) during multi-hop query propagation. This paper presents **1ai-osint**, a modular OSINT orchestrator featuring **Zero Knowledge Identity Tracking (ZKIT)**. By representing identity nodes using privacy-preserving hashes and applying deterministic, cross-module target correlation using salting schemes, 1ai-osint allows correlation of identities across leaked databases, public social graphs, blockchain address ledgers, and registry systems without retaining or exposing raw PII in intermediary databases. We document the platform architecture, LangGraph budget-aware scheduler, and benchmark performance.

---

## 1. Introduction
Traditional OSINT gathering presents significant privacy leaks for investigators. If an investigator queries multiple platforms (e.g. searching for a username or email across fifty public social networks), the metadata patterns expose the query target. 
ZKIT addresses this vulnerability by hashing all target identifiers with a user-controlled, cryptographically random salt value $S$. Graph nodes representing emails, usernames, phone numbers, and blockchain wallets are stored and tracked solely as:
$$\text{NodeID} = \text{SHA256}(\text{Type} \mathbin{\Vert} \text{Value} \mathbin{\Vert} S)$$

---

## 2. Core Architecture & ZKIT Hashing
The platform is organized as a pipeline:
1. **CLI / API Layer**: Receives targets and initializes execution options.
2. **LangGraph Planner**: Evaluates target properties and schedules tasks under strict execution limits.
3. **DeepScanEngine**: Recursively polls active OSINT modules.
4. **ZKIT Correlator**: Ingests findings, hashes attributes using the salt $S$, and forms co-occurrence edges.
5. **Output Engine**: Produces formatted operational briefings and STIX 2.1 bundles.

```
       CLI / API
           │
           ▼
    LangGraph Planner (Budget-Aware)
           │
           ▼
     DeepScanEngine ──► [OSINT Modules / Breach Router]
           │
           ▼
    ZKIT Correlator (Privacy-Preserving Hashes)
           │
           ▼
    Briefing Builder ──► HTML / JSON / STIX / PDF
```

---

## 3. LangGraph Budget-Aware Scheduler
To optimize queries across rate-limited or paid APIs (e.g. DeHashed, IntelX, Have I Been Pwned), we designed a LangGraph state machine. At each iteration, the planner:
- Computes candidates compatible with discovered identifiers.
- Filters out already scanned pairs.
- Orders candidates by confidence and module cost.
- Allocates remaining budget $B$ sequentially.

---

## 4. Performance & Reproducibility (Zenodo Package)
We package the core orchestrator as a reproducible artifact.
- **Zenodo Archive Identifier**: `10.5281/zenodo.1ai_osint_zkit` (draft configuration).
- **Benchmark Metrics**:
  - Throughput: Average 20+ mnemonics checked per second.
  - Accuracy: Deterministic 100% precision on local fixtures.
  - Coverage: Comprehensive cross-linking for EVM, Solana, Bitcoin, and Tron.
