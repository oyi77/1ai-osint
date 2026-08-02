---
scope: vuln_scanner
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# vuln_scanner

> Last updated: correct stale NVD API / CVE database / httpx claims — actual backend is a scan4all subprocess wrapper (commit 8fa2bbf)

## Purpose
Vulnerability scanning module — wraps the scan4all binary to run PoC / port-scan / fingerprint checks on targets and maps results into findings.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Full `VulnScannerTool` implementation (207 lines) — scan4all subprocess wrapper, output parsing, severity mapping |

## For AI Agents

### Working In This Directory
- Runs the `scan4all` CLI via subprocess (installed with `go install github.com/GhostTroops/scan4all@latest`); no NVD API / CVE database integration
- `SUPPORTED_MODES = ("quick", "full", "fingerprint")`; command built in `_build_command` (e.g. quick → `-scan pocv2 -fingerprinthash true`)
- `_parse_output` reads JSON lines into findings (confidence 0.8) with severity via `_map_severity`
- Requires `scan4all` on PATH (or pass `binary_path`); `_validate_binary` checks availability
- Results feed into the deep scan pipeline for risk assessment

## Dependencies

### External
- `scan4all` binary (Go; GhostTroops/scan4all) on PATH

### Internal
- `src/core/` — models and config

<!-- MANUAL: -->
