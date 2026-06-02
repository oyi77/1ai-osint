<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# output

## Purpose
Report generation — formats findings into JSON, PDF, and SARIF output formats.

## Key Files
| File | Description |
|------|-------------|
| `report_generator.py` | Main report generation orchestrator |
| `json_formatter.py` | JSON output formatter |
| `pdf_export.py` | PDF export logic |
| `pdf_generator.py` | PDF document generation |
| `sarif_formatter.py` | SARIF format output |
| `sarif.py` | SARIF schema and utilities |
| `zkit_formatter.py` | ZKIT protocol formatted output |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `json/` | JSON format specifics |
| `pdf/` | PDF template and assets |
| `sarif/` | SARIF format specifics |

## For AI Agents

### Working In This Directory
- All formatters produce output from standardized Finding/ScanResult models
- PDF generation uses reportlab or similar
- SARIF is the standard for security tool interoperability

<!-- MANUAL: -->
