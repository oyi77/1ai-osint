---
scope: report_engine
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# report_engine

> Last updated: document full ReportEngine implementation (was "package initializer"), note SARIF/PDF status (commit 8fa2bbf)

## Purpose
Report engine — generates formatted intelligence reports from scan findings, with HTML rendering.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Full implementation: `ReportFormat` enum (HTML/JSON/SARIF/PDF), `ReportSection`, `ReportData`, `ReportEngine` (line 96) |
| `html_template.py` | `render_html(report)` (line 10) — HTML report template rendering |

## For AI Agents

### Working In This Directory
- `ReportEngine.from_scan_results` extracts identifiers (email, @username, phone, domain, IP, hex addresses) via regex and builds sections
- `parse_report_json` / `extract_identifiers_for_scan` support JSON round-trip and identifier reuse
- `ReportFormat.SARIF` and `ReportFormat.PDF` are declared in the enum but no renderer exists yet — only `render_html` is implemented
- Findings aggregated from multiple scan modules

## Dependencies

### Internal
- `src/core/` — models and finding data
- `src/modules/deep_scan/` — dossier compilation

<!-- MANUAL: -->
