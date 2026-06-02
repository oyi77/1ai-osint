<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# analyzers

## Purpose
Core AI analysis engines for processing OSINT data — entity extraction, correlation, and risk scoring.

## Key Files
| File | Description |
|------|-------------|
| `correlation_engine.py` | Correlates findings across data sources |
| `entity_extractor.py` | Extracts entities (emails, wallets, names) from raw data |
| `risk_scorer.py` | Assigns risk scores to findings |

## For AI Agents

### Working In This Directory
- Each analyzer is a standalone module with async methods
- Test files mirror names: `test_correlation_engine.py`, etc.

## Dependencies

### Internal
- `src/ai/prompts/` — prompt templates for LLM calls
- `src/ai/schemas/` — response validation
- `src/ai/orchestrator.py` — coordinates analyzer calls

<!-- MANUAL: -->
