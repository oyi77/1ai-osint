<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# ai

## Purpose
AI analysis layer — orchestrates LLM calls for entity extraction, correlation analysis, risk scoring, and false positive filtering.

## Key Files
| File | Description |
|------|-------------|
| `orchestrator.py` | Main AI pipeline orchestrator — coordinates analyzers |
| `omniroute_client.py` | LLM API client for AI inference |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `analyzers/` | Core analysis engines — correlation, entity extraction, risk scoring (see `analyzers/AGENTS.md`) |
| `prompts/` | LLM prompt templates (see `prompts/AGENTS.md`) |
| `schemas/` | Response schemas for AI outputs (see `schemas/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- All analyzers are async and called via the orchestrator
- Prompts in `prompts/` define the LLM interaction patterns
- Schemas in `schemas/` validate AI responses

### Common Patterns
- Analyzer classes follow a common interface
- Prompts use f-string templates with structured output expectations

## Dependencies

### Internal
- `src/models.py` — data models for findings and scan results

### External
- httpx — LLM API calls

<!-- MANUAL: -->
