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
| `benchmark.yml` | Benchmark workflow — manual dispatch or on push to main touching `src/**` |
| `pages.yml` | Docs Pages workflow — GitHub Pages deploy of the mkdocs `site/` on push to main |
| `release.yml` | Release workflow — triggered on `v*` tags |
| `docs-sync.yml` | Docs Sync workflow — runs on push to main |

## For AI Agents

### Working In This Directory
- Changes here affect all PRs and pushes
- Test locally before modifying CI config
- `soak.yml` runs `scripts/soak.py` (manual dispatch or on push to main) and uploads the JSON receipt as an artifact

<!-- MANUAL: -->
> Last updated: fix pass — document all 6 workflows (added benchmark.yml, pages.yml, release.yml, docs-sync.yml rows)
