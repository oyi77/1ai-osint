<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# sarif

## Purpose
SARIF (Static Analysis Results Interchange Format) output for security tool interoperability.

## For AI Agents

### Working In This Directory
- SARIF is an OASIS standard for security findings
- Used for integration with GitHub Code Scanning and other SAST tools
- `ReportGenerator` emits SARIF via `sarif_formatter.py` (`SARIFFormatter`) with PII hashing — `sarif.py` is a legacy no-hash path (see `../AGENTS.md`)

> Last updated: noted wired SARIF path via `sarif_formatter.py` (commit 8fa2bbf)

<!-- MANUAL: -->
