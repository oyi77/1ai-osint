# 1ai-osint — Verified Evolution Plan

**Date:** 2026-07-31
**Rule:** Every claim grounded in verified source code. Zero fabrications.

---

## Quick-Impact Wins (≤1 day each)

### 1. Remove Dead Plugin Scaffolding

**Ground truth:** `src/plugin/` has `registry.py`, `base.py`, `hooks.py`, `example.py`. `HookDispatcher` is never instantiated. `init_plugins()` is only called from CLI `plugins` command. The entire system integrates nowhere — it's standalone scaffolding.

**Action:**
- Delete `src/plugin/` entirely
- Remove `plugins` CLI command from `src/cli/app.py` (or replace with a stub that says "deprecated")
- Delete `src/plugins/example_plugin.py`

**Verification:** `grep -r "init_plugins\|HookDispatcher\|import.*plugin" src/ --include="*.py"` → only the CLI commands module. After deletion: `pytest tests/ -x -q` passes.

**Risk:** None — dead code removal. Rollback via git revert.

---

### 2. Remove Dead Profile Entry (`darknet`)

**Ground truth:** `src/modules/deep_scan/scan_profiles.py` declares `darknet` in `DEEP_EXTRA`. It has no module anywhere: not in `SOURCE_MODULES` (`_module_config.py:62` — `{dehashed, leakcheck, snylla, snusbase, hibp, intelx}`), no `get_module()` branch in `src/cli/helpers.py:31-77`, no entry in `src/modules/__init__.py` registry. `src/modules/sources/darknet_source.py` exists (a `DarknetSource` class) but has zero importers in `src/`. In deep scan, the engine hits `engine.py:380` → `_get_module('darknet')` returns `None` → silently skipped. It is a pure no-op entry.

**Action:**
- Remove `darknet` from the `DEEP_EXTRA` tuple in `scan_profiles.py`
- (Keep `crypto_tracer` — that module IS real; its gap is missing dispatch wiring, tracked as item 9 below)

**Verification:** `grep -r "darknet" src/modules/deep_scan/ --include="*.py"` → only `threat_model.py` string comparisons remain (finding-label checks, unaffected). After deletion: `pytest tests/unit/test_scan_profiles.py tests/integration/test_deep_scan_golden.py -q` passes.

**Risk:** None — this entry is an unreachable no-op. Removing it changes no runtime behavior.

---

### 3. Evaluate Vendor Consolidation: `modules/vendor/` vs `vendor/chiasmodon/`

**Ground truth:** Two separate vendor trees exist. `src/modules/vendor/` has `ExternalToolIntel` (179 lines, imported by `deep_scan/engine.py:210`) with 3 mixins (242 lines total) — provides general OSINT tool orchestration. `src/vendor/chiasmodon/` has 37 files — 15 leak tools + 19 providers + `pychiasmodon` client + base framework — imported by `data_leaks/aggregator.py`, `people_finder/search.py`, `phone_finder/lookup.py`. Both are alive and actively used.

**Potential action:**
- Audit whether `ExternalToolIntel` in `modules/vendor/` duplicates functionality already covered by the chiasmodon provider suite
- If overlap exists, consolidate into `vendor/chiasmodon/` and delete `modules/vendor/`
- If they serve different roles (general OSINT orchestration vs specific leak tools), document the boundary
- This is an architectural audit, not a delete

**Verification:** Trace which providers each tree wraps. Check if deep_scan's vendor tools run the same sherlock/maigret/holehe as chiasmodon's providers. Report findings before acting.

**Risk:** Low if read-only audit; moderate if deleting — both trees have real callers.

---

### 4. Fix `docs-sync.yml` Version Badge Sync

**Ground truth:** `docs-sync.yml` uses a fragile `sed -i "s/version-[0-9.]\+/version-$VERSION/g" README.md` that will fail if the version format changes or README.md lacks an existing version badge.

**Action:**
- Replace `sed` with Python inline script using `re.sub(r'version-\d+\.\d+\.\d+-?\w*', f'version-{version}', README.md)`
- Add idempotent fallback: if no match found, add a badge at the top of README.md

**Verification:** Test with dry-run on README.md. The file only changes on version bump.

---

## Medium-Term Improvements (2-5 days each)

### 5. PyPI Publish Step in `release.yml`

**Ground truth:** `release.yml` (triggered on `v*` tags) builds wheel+sdist (`python -m build`) and creates a GitHub Release. It never publishes to PyPI. The package is installable from source but not `pip install 1ai-osint`.

**Action:**
- Generate PyPI API token for the project
- Add `pypa/gh-action-pypi-publish@release/v1` step in `release.yml` after build
- Ensure `pyproject.toml` has correct `[project.urls]`, `long_description`, `classifiers` for PyPI

**Verification:** Create a test tag (`git tag v0.1.0-test`), push, verify it publishes to TestPyPI first. Then remove test tag. Production tag publishes to real PyPI.

**Rollback:** Remove the publish step. Delete the release from PyPI (if needed).

---

### 6. Add Docker Publish to `release.yml`

**Ground truth:** `release.yml` builds the Docker image (`docker build -t 1ai-osint:$TAG_NAME ...`) but never pushes it to a registry.

**Action:**
- Add `docker/login-action@v3` with GitHub Container Registry credentials
- Add `docker push` step after build
- Tag with `ghcr.io/<org>/1ai-osint:${{ github.ref_name }}` and `:latest`

**Verification:** After next release tag, verify image is published to GHCR.

---

### 7. Migrate Dockerfile from pip to uv

**Ground truth:** `Dockerfile` uses `pip install --no-cache-dir ".[dev]"` in the builder stage. `pyproject.toml` uses `uv` as its primary tool (`[tool.uv]` section). The project's GitHub Actions all use `astral-sh/setup-uv@v3`. The Dockerfile is inconsistent.

**Action:**
- Replace `pip install` with `uv sync --group dev --frozen` in the builder stage
- Copy `.venv` from builder to runtime instead of site-packages
- This gives correct dependency resolution matching local dev

**Verification:** `docker build -t 1ai-osint:test .` succeeds. Smoke test: `docker run --rm 1ai-osint:test --help` prints help.

---

### 8. Add Web Auth Layer

**Ground truth:** `src/web/main.py` creates a FastAPI app with no authentication middleware. All 11 web routes are publicly accessible.

**Action:**
- Add API key auth via `fastapi.Security` / `fastapi.Depends`
- Support header-based (`X-API-Key`) and query-param auth
- Key stored in config (env var or config file)
- Document in code and README

**Verification:** `curl -X GET http://localhost:8080/` returns 401 without key, 200 with valid key. All routes inherit the dependency.

---

### 9. Wire Missing Dispatch for Real Modules (`ai_enricher`, `crypto_tracer`)

**Ground truth:** Two modules are registered/real but never run by deep scan because they lack dispatch wiring:
- `src/modules/free_intel/ai_enricher.py` (117 lines) has a real `AIExtractor` class with LLM-based analysis, but it is **NOT registered** in `_FREE_INTEL_DISPATCH`, `_MODULE_INPUTS`, or `get_module()`. It has zero importers across `src/` — it's orphaned. Per the audit learning: "The ai_enricher module must be excluded from the direct adapter pattern — it needs cross-module context from other scan results, not just a single string target."
- `crypto_tracer` IS a real module — `BlockchainTxTracer` (262 lines, `src/modules/crypto/tx_tracer.py`, real Etherscan+Blockchair+Solana APIs with mock fallback), registered in `src/modules/__init__.py:46`, listed in `FAST_SKIP_MODULES`, the builtin deep profile, and `_VALID_MODULES` (`deep_scan/profiles.py`), and consumed by `timeline_builder.py:94` (`finding.module == "crypto_tracer"`). It is missing only the `get_module()` branch in `src/cli/helpers.py:31-77` — so `engine.py:380-382` resolves `None` and silently skips it. This is a functionality gap, not dead code.

**Action:**
- `ai_enricher`: add an `enrich_from_results()` entry point that accepts `List[ScanResult]` (the full scan output) instead of a single `name: str`; wire it into `deep_scan/engine.py`'s post-processing phase (after all other modules complete); keep the single-target `scan(name)` proxy for backwards compatibility
- `crypto_tracer`: add `elif name in ("crypto_tracer", "tx_tracer"): from src.modules.crypto.tx_tracer import BlockchainTxTracer; return BlockchainTxTracer(zkit_salt=zkit_salt)` to `cli/helpers.get_module()`; verify `_MODULE_INPUTS` accepts crypto targets so the engine routes wallet/address/tx identifiers to it

**Verification:** A deep scan with AI enrichment enabled attaches richer LLM context in the final report output; a deep scan on a crypto address produces `crypto_tracer` findings with `transactions` raw_data that `timeline_builder` picks up. Test both the single-target and cross-module paths.

---

## Strategic Architecture Items (>1 week each)

### 10. Wire Plugin System or Delete It

**Ground truth:** The plugin scaffolding exists but is unused. The correct decision depends on whether the project wants third-party plugin support (unlikely for a security tool) or not.

**Options:**
- **Delete** (recommended, 1 day): Remove `src/plugin/`, CLI `plugins` command. Same as Quick-Impact #1.
- **Wire it** (1+ week): Hook plugin `before_scan`/`after_scan`/`on_finding` callbacks into `DeepScanEngine._run_iteration()`. This requires integrating the dispatcher into 5+ engine methods.

**Recommendation:** Delete. Security tools don't benefit from third-party plugins — the risk of malicious plugins is not worth the convenience. If extensibility is needed, the existing module discovery in `sources/` and `free_intel/` provides a better extension model.

---

### 11. Add Documentation Site

**Ground truth:** REPO contains comprehensive docs (`CODEBASE.md`, `README.md`, `docs/ROADMAP.md`) but no hosted documentation site. The ROADMAP mentions platform maturity but not docs publishing.

**Action:**
- Add `mkdocs` or `sphinx` configuration
- Add docs build to `ci.yml` (run on PRs to catch doc breakage)
- Add docs deployment step in `release.yml` or `docs-sync.yml`
- Publish to GitHub Pages (`gh-pages` branch or Pages deployment)

**Verification:** After merge, `https://<org>.github.io/1ai-osint/` shows rendered docs.

---

### 12. Build CLI on `uv tool` or Docker Entry Point

**Ground truth:** Currently `python -m src.cli` only. No `pipx` or `uv tool` entry point. Docker ENTRYPOINT is `python -m src.cli` (via `-m`).

**Action:**
- Add `[project.scripts]` entry in `pyproject.toml`: `1ai-osint = "src.cli.app:main"`
- Verify `pip install -e .` creates a global `1ai-osint` command
- Update Docker CMD to use the CLI entry instead of `python -m`

**Verification:** `pip install -e . && 1ai-osint --help` shows CLI. `1ai-osint doctor` runs. `docker run --rm 1ai-osint:latest` also uses the entry point.

---

## Appendix: Verified Gaps Summary

| # | Gap | Tier | Evidence | Difficulty |
|---|-----|------|----------|------------|
| 1 | Dead plugin scaffolding | Dead code | `src/plugin/` — never integrated | 1 hour |
| 2 | Dead profile entry (`darknet`) | Dead code | `DEEP_EXTRA` in scan_profiles.py — no module exists anywhere | 30 min |
| 3 | `report_engine/` | Alive | 2 files, imported in 6 places (scan_commands.py) | Already done |
| 4 | `vendor/` trees | Alive | `modules/vendor/` (5 files, 179+242 loc) + `vendor/chiasmodon/` (37 files). Both have real callers. | Architectural audit (not delete) |
| 5 | Fragile sed in docs-sync.yml | Fragile CI | `release.yml` sed pattern | 30 min |
| 6 | No PyPI publish | Missing capability | `release.yml` has no publish step | 1 day |
| 7 | Docker image not pushed | Missing capability | `release.yml` builds but doesn't push | 1 day |
| 8 | Dockerfile uses pip, not uv | Inconsistency | Project standard is uv | 2 hours |
| 9 | Web UI has no auth | Security gap | `src/web/main.py` — no middleware | 1-2 days |
| 10 | Dispatch gap: `ai_enricher` + `crypto_tracer` | Functionality gap | 117 + 262 real lines, zero dispatch wiring — not in `get_module()` | 2-3 days |
| 11 | Plugin system: wire or delete | Architecture debt | Standalone scaffolding | 1 day delete / 1 week+ wire |
| 12 | No docs site | Missing capability | No mkdocs/sphinx config | 2-3 days |
| 13 | No pipx/uv tool entry | Missing capability | No `[project.scripts]` in pyproject.toml | 1 hour |

## Quick Summary

```
┌──────────────────────────────────────────────────┐
│  1-3 days:  Clean dead plugin scaffolding; audit vendor consolidation     │
│             Fix fragile CI sed                     │
│             Add [project.scripts] for CLI          │
├──────────────────────────────────────────────────┤
│  1-2 weeks: PyPI + Docker publish in release CI   │
│             Docker uv migration                    │
│             Web auth layer                         │
│             ai_enricher cross-module context        │
├──────────────────────────────────────────────────┤
│  Strategic:  Docs site (mkdocs/sphinx + Pages)     │
│             Decision on plugin system (wire/del)  │
└──────────────────────────────────────────────────┘
```

Every item above references exact files verified during the codebase audit. No speculations, no ROADMAP aspirations — only confirmed gaps.
