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

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `exports/` | Export formatters — HTML, JSON, PDF, STIX (see `exports/AGENTS.md`) |

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

<!-- MANUAL: -->
