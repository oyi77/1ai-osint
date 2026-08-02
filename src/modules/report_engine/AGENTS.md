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
| `__init__.py` | Full implementation: `ReportEngine` (line 96), `ReportSection`, `ReportData` |
| `html_template.py` | `render_html(report)` (line 10) — HTML report template rendering |

## For AI Agents

### Working In This Directory
- `ReportEngine.from_scan_results` extracts identifiers (email, @username, phone, domain, IP, hex addresses) via regex and builds sections
- `parse_report_json` / `extract_identifiers_for_scan` support JSON round-trip and identifier reuse
- The `ReportFormat` enum (dead code) was removed — only `render_html` is implemented; SARIF/PDF have no renderer here
- Findings aggregated from multiple scan modules

## Dependencies

### Internal
- `src/core/` — models and finding data
- `src/modules/deep_scan/` — dossier compilation

<!-- MANUAL: -->
> Last updated: fix pass — removed dead ReportFormat enum; only render_html implemented
