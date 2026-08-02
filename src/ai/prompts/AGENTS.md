---
scope: src/ai/prompts
depends_on: []
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# prompts

## Purpose
LLM prompt templates for AI-powered analysis tasks.

## Key Files
| File | Description |
|------|-------------|
| `entity_extraction.py` | Prompts for extracting entities from raw leak data (`ENTITY_EXTRACTION_PROMPT`) |
| `false_positive_filter.py` | Prompts for filtering false positives from findings (`FALSE_POSITIVE_PROMPT`) |
| `behavioral_analysis.py` | Prompts for behavioral profiling (`BEHAVIORAL_ANALYSIS_PROMPT`) |
| `anomaly_detection.py` | Prompt for LLM anomaly enrichment (`ANOMALY_DETECTION_PROMPT`) |

## Exports (`__init__.py`)
Re-exported: `ENTITY_EXTRACTION_PROMPT`, `FALSE_POSITIVE_PROMPT`, `BEHAVIORAL_ANALYSIS_PROMPT`.

Not re-exported: `ANOMALY_DETECTION_PROMPT` — consumers import it directly from `anomaly_detection.py` (e.g. `src/ai/analyzers/anomaly_detector.py`).

## For AI Agents

### Working In This Directory
- Prompts are Python modules with template strings
- Use f-string or .format() patterns for dynamic content
- Keep prompts focused — one task per prompt template

<!-- MANUAL: -->

> Last updated: added frontmatter; added behavioral_analysis.py and anomaly_detection.py to Key Files; documented `__init__.py` re-exports and `ANOMALY_DETECTION_PROMPT` export gap (commit 8fa2bbf)
