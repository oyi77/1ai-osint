<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# pdf

## Purpose
PDF report template and assets for generating human-readable reports.

## For AI Agents

### Working In This Directory
- PDF generation uses reportlab
- Templates and assets for report formatting
- `ReportGenerator` renders PDFs via `pdf_generator.py` (`PDFGenerator`), which hashes the target; the legacy `pdf_export.py` is deprecated and now also hashes the target (`pdf_export.py:12-15,47`) — see `../AGENTS.md`

> Last updated: noted wired PDF path via `pdf_generator.py` (commit 8fa2bbf)

<!-- MANUAL: -->
> Last updated: fix pass — legacy pdf_export.py now hashes target too (pdf_export.py:12-15,47), deprecated
