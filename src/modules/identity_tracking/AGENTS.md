<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# identity_tracking — ZKIT Core

## Purpose
The heart of ZKIT (Zero Knowledge Identity Tracking). Privacy-preserving identity correlation and graph analysis — links entities across all OSINT data sources without requiring prior knowledge of the target. All other modules feed findings here for cross-referencing.

## Key Files
| File | Description |
|------|-------------|
| `correlation.py` | Correlates identities across different data sources |
| `identity_graph.py` | Builds and queries identity relationship graphs |
| `zkit_engine.py` | ZKIT protocol engine for identity analysis |

## For AI Agents

### Working In This Directory
- Correlation engine links entities by email, wallet, phone, name
- Identity graph stores relationships for traversal
- ZKIT engine implements the ZKIT protocol (see `docs/ZKIT_PROTOCOL.md`)

<!-- MANUAL: -->
