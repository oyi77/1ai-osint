<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# vuln_scanner

## Purpose
Vulnerability scanning module — CVE lookup, service fingerprinting, and known vulnerability correlation.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Full `VulnScannerTool` implementation (207 lines) — CVE database, NVD integration, service discovery |

## For AI Agents

### Working In This Directory
|- **Full implementation** — `VulnScannerTool` class with CVE lookup, NVD API integration, and service vulnerability correlation
|- Scans discovered services and technologies against known CVEs
|- Integrates with NVD API for CVE details and severity scoring
|- Results feed into deep scan pipeline for risk assessment

## Dependencies

### External
- httpx — async HTTP for CVE/NVD API calls

### Internal
- `src/core/` — models and config

<!-- MANUAL: -->
