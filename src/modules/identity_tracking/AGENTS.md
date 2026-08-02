---
scope: identity_tracking
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# identity_tracking — ZKIT Core

> Last updated: document full module surface (10 files incl. counterintel, behavioral fingerprint, neo4j export) and Neo4j password posture (commit 8fa2bbf)

## Purpose
The heart of ZKIT (Zero Knowledge Identity Tracking). Privacy-preserving identity correlation and graph analysis — links entities across all OSINT data sources without requiring prior knowledge of the target. All other modules feed findings here for cross-referencing.

## Key Files
| File | Description |
|------|-------------|
| `correlation.py` | `CorrelationSource`, `ResolvedEntity`, `CorrelationResult`, `CrossModuleCorrelator` (line 59) — correlates identities across data sources |
| `identity_graph.py` | `IdentityGraph` (line 29) — builds and queries identity relationship graphs |
| `zkit_engine.py` | `ZKITEngine` (line 44) — ZKIT protocol engine for identity analysis |
| `counterintel.py` | `OPSECLevel`, `LegendIndicator`, `CounterIntelAssessment`, `CounterIntelAnalyzer` (line 51) — OPSEC counterintel analysis (not exported in `__all__`) |
| `behavioral_fingerprint.py` | `PotentialMatch`, `BehavioralFingerprint`, `LinguisticFingerprintAnalyzer` (line 107) — behavioral fingerprinting (not exported in `__all__`) |
| `neo4j_export.py` | `Neo4jClient` (line 84) — Neo4j import/export; `__all__` at line 410 |
| `_zkit_types.py` | Shared types: `CorrelationConfidence`, `IngestedRecord`, `CorrelatedCluster`, `ZKITOutput`; `PII_FIELDS` (line 27), `normalize_attribute` (line 49) |
| `_graph_models.py` | `NodeType`, `GraphNode`, `GraphEdge` |
| `_neo4j_helpers.py` | `collect_nodes` / `collect_edges`, `export_neo4j_json` / `load_neo4j_json`; reads `NEO4J_PASSWORD` from env (line 22) |
| `__init__.py` | Exports the 16 public symbols listed in `__all__` (line 32) |

## For AI Agents

### Working In This Directory
- Correlation engine links entities by email, wallet, phone, name
- Identity graph stores relationships for traversal
- ZKIT engine implements the ZKIT protocol (see `docs/ZKIT_PROTOCOL.md`)
- Security posture: `_neo4j_helpers.py:22` falls back to a hardcoded default password when `NEO4J_PASSWORD` is unset — set it in production; no secret values are committed anywhere in this module

## Dependencies

### Internal
- `src/core/` — models, cache, rate limiting

<!-- MANUAL: -->
