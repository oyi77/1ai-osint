<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-01 -->

# workflows

## Purpose
GitHub Actions CI + soak pipelines.

## Key Files
| File | Description |
|------|-------------|
| `ci.yml` | Main CI workflow — lint, test, coverage, pip-audit |
| `soak.yml` | Soak workflow — network-free `RateLimiter` + `Cache` soak, uploads receipt artifact |

## For AI Agents

### Working In This Directory
- Changes here affect all PRs and pushes
- Test locally before modifying CI config
- `soak.yml` runs `scripts/soak.py` (manual dispatch or on push to main) and uploads the JSON receipt as an artifact

<!-- MANUAL: -->
