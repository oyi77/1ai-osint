---
scope: src/ai/analyzers
depends_on: [src/ai/prompts, src/ai/schemas]
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# analyzers

## Purpose
Core AI analysis engines for processing OSINT data — entity extraction, correlation, risk scoring, behavioral profiling, and anomaly detection.

## Key Files
| File | Description |
|------|-------------|
| `entity_extractor.py` | Extracts entities (emails, wallets, names) from raw data (`EntityExtractor`) |
| `correlation_engine.py` | Correlates findings across data sources (`CorrelationEngine`) |
| `risk_scorer.py` | Assigns risk scores to findings (`RiskScorer`, `RiskScore`, `RiskBreakdown`) |
| `behavioral_profiler.py` | Behavioral profiling of entities / text (`BehavioralProfiler`) |
| `anomaly_detector.py` | Detects anomalies in findings (`AnomalyDetector`) |
| `_anomaly_utils.py` | Shared helpers — `build_summary`, `parse_llm_anomalies` (delegated by `AnomalyDetector`) |

## For AI Agents

### Working In This Directory
- Analyzer methods are synchronous (`def`, not `async def`) — the orchestrator calls them directly
- Test files mirror names: `test_correlation_engine.py`, etc.
- `anomaly_detector.py` delegates `build_summary` / `parse_llm_anomalies` to `_anomaly_utils.py`

## Dependencies

### Internal
- `src/ai/prompts/` — prompt templates for LLM calls
- `src/ai/schemas/` — response validation
- `src/ai/orchestrator.py` — coordinates analyzer calls

<!-- MANUAL: -->

> Last updated: added frontmatter; added behavioral_profiler.py, anomaly_detector.py, _anomaly_utils.py to Key Files; corrected async claim — analyzers are synchronous (commit 8fa2bbf)
