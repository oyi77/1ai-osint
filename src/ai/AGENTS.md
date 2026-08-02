---
scope: src/ai
depends_on: [src/core, src/ai/analyzers, src/ai/prompts, src/ai/schemas]
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# ai

## Purpose
AI analysis layer — orchestrates LLM calls for entity extraction, correlation analysis, risk scoring, and false positive filtering.

## Key Files
| File | Description |
|------|-------------|
| `orchestrator.py` | Main AI pipeline orchestrator (`AnalysisOrchestrator`, LangGraph `StateGraph`) — coordinates analyzers |
| `omniroute_client.py` | LLM API client for AI inference (`OmniRouteClient`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `analyzers/` | Core analysis engines — correlation, entity extraction, risk scoring, profiling, anomaly detection (see `analyzers/AGENTS.md`) |
| `prompts/` | LLM prompt templates (see `prompts/AGENTS.md`) |
| `schemas/` | Response schemas for AI outputs (see `schemas/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Analyzer methods are synchronous (`def`) — the orchestrator drives them; `omniroute_client.py` additionally exposes async variants (`async_chat`, `async_extract_entities`, `async_filter_false_positives`, `async_chat_multimodal`)
- Prompts in `prompts/` define the LLM interaction patterns
- Schemas in `schemas/` validate AI responses

### Common Patterns
- Analyzer classes follow a common interface
- Prompts use f-string templates with structured output expectations

## Dependencies

### Internal
- `src/core/models.py` — data models for findings and scan results

### External
- httpx — LLM API calls

<!-- MANUAL: -->

> Last updated: added frontmatter; corrected async claim — analyzer methods are synchronous, not async; internal deps now point to `src/core/models.py` (commit 8fa2bbf)
