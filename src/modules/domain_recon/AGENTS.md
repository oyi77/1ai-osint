---
scope: domain_recon
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# domain_recon

> Last updated: correct line count (253), fix stale subfinder/amass/nmap claim, clean table formatting (commit 8fa2bbf)

## Purpose
Domain reconnaissance — WHOIS lookup, DNS enumeration, subdomain discovery, certificate transparency, and technology fingerprinting via HTTP APIs.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Full `DomainReconTool` implementation (253 lines) — WHOIS, DNS ANY, crt.sh subdomains/CT, tech-stack fingerprinting |
| `infra_fingerprint.py` | `InfraFingerprint` / `InfraCluster` / `InfraFingerprintEngine` — IP-info based infrastructure fingerprinting. Standalone; not imported by `__init__.py` |

## For AI Agents

### Working In This Directory
- Pure httpx-based API calls — no subfinder/amass/nmap subprocess integration
- `scan()` guards targets via `src.core.ssrf_guard.validate_scan_target` (targets blocked by SSRF policy return status "blocked")
- Five parallel gather tasks: `_whois_lookup` (arin.net REST), `_dns_enumeration` (dns.google `type=ANY`), `_subdomain_discovery` (crt.sh), `_certificate_transparency` (crt.sh), `_tech_stack_detection` (HTTP headers)
- Rate-limited: 30 RPM, burst 5
- Results feed into identity correlation and graph analysis

## Dependencies

### Internal
- `src/core/` — models and config
- `src/core/ssrf_guard.py` — scan-target validation
- `src/modules/identity_tracking/` — correlation engine

<!-- MANUAL: -->
