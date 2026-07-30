<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# domain_recon

## Purpose
Domain reconnaissance — subdomain enumeration, technology fingerprinting, and infrastructure analysis.

## Key Files
| File | Description |
||------|-------------|
|| `__init__.py` | Full `DomainReconTool` implementation (233 lines) — subdomain enumeration, technology fingerprinting, infrastructure analysis |
|| `infra_fingerprint.py` | Technology stack and infrastructure fingerprinting |

## For AI Agents

### Working In This Directory
- Integrates with external recon tools (subfinder, amass, nmap)
- Results feed into identity correlation and graph analysis

## Dependencies

### Internal
- `src/core/` — models and config
- `src/modules/identity_tracking/` — correlation engine

<!-- MANUAL: -->
