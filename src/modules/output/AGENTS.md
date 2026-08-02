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
- All formatters produce output from standardized Finding/ScanResult models (`src/core/models.py`)
- `ReportGenerator` is the orchestrator — it uses `json_formatter.py`, `sarif_formatter.py`, and `pdf_generator.py` only
- PII is hashed (SHA-256, salted) in the wired formatters — `json_formatter.py`, `sarif_formatter.py`, `pdf_generator.py`
- **Legacy paths:** `pdf_export.py` (prints raw `scan_result.target` unhashed) and `sarif.py` (no PII hashing) are NOT used by `ReportGenerator` — prefer the wired formatters
- PDF generation uses reportlab
- SARIF is the standard for security tool interoperability

> Last updated: added PII-hashing note and legacy formatter warnings (`pdf_export.py`, `sarif.py`) (commit 8fa2bbf)

<!-- MANUAL: -->
