<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# exports

## Purpose
Export formatters for deep scan results — HTML dossiers, JSON data exports, PDF briefings, and STIX 2.1 threat intelligence bundles.

## Key Files
| File | Description |
|------|-------------|
| `dossier_html.py` | HTML dossier template rendering |
| `html_export.py` | HTML export utilities |
| `json_export.py` | JSON data serialization |
| `pdf_briefing.py` | PDF intelligence briefing generation |
| `stix_export.py` | STIX 2.1 threat intelligence export |
| `__init__.py` | `export_report(report, fmt="html")` — format dispatcher for all exporters |

## For AI Agents

### Working In This Directory
- Each exporter produces a different output format from the same data
- Follow existing format patterns when adding new exporters

## Dependencies

### Internal
- `src/modules/deep_scan/` — scan result models
- `src/core/models.py` — shared data models

> Last updated: added `__init__.py` `export_report()` dispatcher (commit 8fa2bbf)

<!-- MANUAL: -->
