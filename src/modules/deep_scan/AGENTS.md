<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# deep_scan

## Purpose
Deep scan engine — comprehensive multi-source OSINT analysis with dossier compilation, AI briefing, timeline building, and threat modeling.

## Key Files
| File | Description |
|------|-------------|
| `engine.py` | Main deep scan orchestrator |
| `deep_scraper.py` | Deep scraping with anti-detection |
| `extractor.py` | Entity and data extraction |
| `name_pivots.py` | Name-based pivot and correlation |
| `profiles.py` | Target profile management |
| `breach_router.py` | Breach data routing across sources |
| `breach_normalizer.py` | Normalizes breach data to common schema |
| `geo_osint.py` | Geospatial intelligence enrichment |
| `ai_analyst.py` | AI-powered analysis of findings |
| `ai_briefing.py` | AI-generated intelligence briefings |
| `delta_briefing.py` | Change detection briefing |
| `briefing_builder.py` | Constructs structured briefing reports |
| `dossier_compiler.py` | Compiles full target dossiers |
| `vision_correlator.py` | Visual/cross-modal correlation |
| `timeline_builder.py` | Builds event timelines |
| `handle_verifier.py` | Social handle verification |
| `scan_profiles.py` | Scan profile definitions |
| `threat_model.py` | Threat modeling and risk assessment |
| `report_generator.py` | Deep scan report generation |
| `source_adapter.py` | Adapter for external source integration |
| `source_status.py` | Data source health tracking |
| `free_intel_adapter.py` | Free intel source integration |
| `agent_loop.py` | Agentic scan loop — `AgentScanPlanner`, step planning/execution, target-type detection |
| `models_report.py` | Report data models — `IntelReport`, `RiskAssessment`, `OperationalBriefing`, `PivotSuggestion` |
| `field_labels.py` | Display labels, source metadata (`_SOURCE_META`), and record-field formatting |
| `_dossier_models.py` | `TargetDossier` and dossier data models |
| `_module_config.py` | `MODULE_INPUTS` / `SOURCE_MODULES` — module → identifier-type config (split out of `engine.py`) |
| `_free_intel_modules.py` | Keyless free-intel runner functions (`run_*_intel`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `exports/` | Export formatters — HTML, JSON, PDF, STIX (see `exports/AGENTS.md`) |
| `templates/` | Jinja2 HTML report templates (`report.html.j2`, `report_intel.html.j2`, `report_briefing.html.j2`) |

## For AI Agents

### Working In This Directory
- Complex multi-step scan pipeline
- AI enrichment uses `src/ai/` layer
- Reports exportable in multiple formats

## Dependencies

### Internal
- `src/ai/` — AI analysis layer
- `src/modules/` — individual OSINT modules
- `src/core/` — models and config

> Last updated: added `agent_loop.py`, `models_report.py`, `field_labels.py`, `_dossier_models.py`, `_module_config.py`, `_free_intel_modules.py`, and `templates/` (commit 8fa2bbf)

<!-- MANUAL: -->
