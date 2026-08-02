---
scope: src/ai/schemas
depends_on: []
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# schemas

## Purpose
Pydantic response schemas for validating AI/LLM outputs.

## Key Files
| File | Description |
|------|-------------|
| `responses.py` | Response model definitions for AI outputs |
| `__init__.py` | Re-exports the public schema surface |

## Exports (`__init__.py`)
Re-exported: `EntityExtractionResult`, `ExtractedEntity`, `FalsePositiveResult`, `FindingAssessment`, `CorrelationResult`, `LanguageStyle`, `ActivityTimes`, `BehavioralProfile`, `BehavioralAnalysisResult`, `DetectedAnomaly`, `AnomalyReport`, `AnomalyDetectionResult`, `RelationshipType`.

Not re-exported (import directly from `responses.py`): `EntityType` — export gap, see below.

## For AI Agents

### Working In This Directory
- Schemas enforce structure on LLM responses
- Update schemas when changing prompt output formats
- Add new models to `__init__.py` `__all__` — `EntityType` is currently missing from the re-export list

<!-- MANUAL: -->

> Last updated: added frontmatter; documented actual `__init__.py` exports; noted `EntityType` (responses.py) missing from re-exports (commit 8fa2bbf)
