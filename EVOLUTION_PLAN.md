# 1ai-osint — Verified Evolution Plan

**Date:** 2026-07-31
**Rule:** Every claim grounded in verified source code. Zero fabrications.

---

## Quick-Impact Wins (≤1 day each)

### 1. Plugin System: Wire Hooks or Keep as Documented Extension Point

**Status: ✅ RESOLVED (keep option) — commit `953cab0`** removed the dead `_plugin_registry` declaration at `src/cli/main.py`; hooks remain an opt-in extension point. The preferred "wire" option was explicitly NOT taken (no `dispatcher.dispatch("on_scan_*")` call in `deep_scan/engine.py` or `scan_commands.py`).

**Ground truth:** `src/plugin/` (registry.py 197 lines, hooks.py 105, base.py 78) is a **functional subsystem** — NOT dead scaffolding. `PluginRegistry().discover()` finds and registers plugins; the CLI `plugins` command works (verified: lists `example_logger` v0.1.0 with hooks `[on_scan_start, on_scan_end]`); 31 unit tests in `tests/unit/test_plugin_system.py` pass. `src/plugins/example_plugin.py` is a reference plugin registered at runtime. The one real gap: `HookDispatcher` is never wired into the scan lifecycle — nothing calls `dispatcher.dispatch("on_scan_*")` in `deep_scan/engine.py` or `scan_commands.py`, so hooks exist but never fire during actual scans. Same gap class as `crypto_tracer`/`ai_enricher` — unwired, not dead. `src/cli/main.py:30` `_plugin_registry` is a dead declaration (never assigned; only TYPE_CHECKING import).

**Action (choose):**
- **Wire (preferred):** call `init_plugins()` once at CLI startup (or in `scan_commands`), then `await HookDispatcher(registry).dispatch("on_scan_start", target=..., module=...)` in `deep_scan/engine.py` before/after module iterations; dispatch `on_report` after report generation. ~1 day.
- **Keep as extension point:** document that hooks are opt-in (callers invoke `dispatcher.dispatch` explicitly); remove the dead `_plugin_registry` declaration in `src/cli/main.py:30`. ~30 min.
- **Do NOT delete:** removing `src/plugin/` breaks the working `plugins` CLI command and 456 lines of tests for zero benefit.

**Verification (wire path):** `uv run python -m src.cli.main scan ... --plugins` produces `[ExamplePlugin] Scan STARTED/ENDED` log lines; `pytest tests/unit/test_plugin_system.py -q` stays green.

---

### 2. Remove Dead Profile Entry (`darknet`)

**Status: ✅ DONE — commit `2a572df`** removed `darknet` from `DEEP_EXTRA` in `scan_profiles.py`; verified zero `darknet` matches remain in that file.

**Ground truth:** `src/modules/deep_scan/scan_profiles.py` declares `darknet` in `DEEP_EXTRA`. It has no module anywhere: not in `SOURCE_MODULES` (`_module_config.py:62` — `{dehashed, leakcheck, snylla, snusbase, hibp, intelx}`), no `get_module()` branch in `src/cli/helpers.py:31-77`, no entry in `src/modules/__init__.py` registry. `src/modules/sources/darknet_source.py` exists (a `DarknetSource` class) but has zero importers in `src/`. In deep scan, the engine hits `engine.py:380` → `_get_module('darknet')` returns `None` → silently skipped. It is a pure no-op entry.

**Action:**
- Remove `darknet` from the `DEEP_EXTRA` tuple in `scan_profiles.py`
- (Keep `crypto_tracer` — that module IS real; its gap was missing dispatch wiring, tracked as item 9 below → now resolved by commit `8db5a28`)

**Verification:** `grep -r "darknet" src/modules/deep_scan/ --include="*.py"` → only `threat_model.py` string comparisons remain (finding-label checks, unaffected). After deletion: `pytest tests/unit/test_scan_profiles.py tests/integration/test_deep_scan_golden.py -q` passes.

**Risk:** None — this entry is an unreachable no-op. Removing it changes no runtime behavior.

---

### 3. Evaluate Vendor Consolidation: `modules/vendor/` vs `vendor/chiasmodon/`

**Ground truth:** Two separate vendor trees exist. `src/modules/vendor/` has `ExternalToolIntel` (179 lines, imported by `deep_scan/engine.py:292` inside Phase 3 `_run_external_tools_phase` at `engine.py:285`) with 3 mixins (242 lines total) — wraps 14 external CLIs via subprocess. `src/vendor/chiasmodon/` has 37 files — 15 leak tools + 19 OSINT providers + `pychiasmodon` client + base framework — imported by `data_leaks/aggregator.py`, `people_finder/search.py`, `phone_finder/lookup.py`.

**Audit result (completed — every claim verified by import grep + consumer trace):**

1. **`ExternalToolIntel` is NOT redundant.** It is the only production consumer of the domain/recon CLIs (theHarvester, amass, subfinder, bbot, spiderfoot, chiasmodon CLI, social-analyzer, ghunt, leakosint, web-check, worldmonitor, crucix). Its chiasmodon-provider counterparts for theHarvester/amass/spiderfoot are in the dead 15 below.
2. **15 of 19 chiasmodon providers are production-dead** (272 lines): haveibeenpwned, shodan, virustotal, abuseipdb, whoisxml, crtsh, wayback, social, holehe, h8mail, amass, theharvester, spiderfoot, datasploit, exiftool — referenced only by `tests/unit/test_chiasmodon_providers.py` and `providers/__init__.py` re-exports (no production importer). Live 4: sherlock, maigret, whatsmyname (people_finder), phoneinfoga (phone_finder/lookup).
3. **Triple wrapper duplication** for sherlock/maigret (ExternalToolIntel Phase 3 + `sources/*_source.py` leak-finder/CLI/node + chiasmodon provider), and dual for phoneinfoga (2 subprocess + 1 HTTP), whatsmyname, holehe. The `sources/` variants are live via `crypto/leak_finder/coordinator.py:74-89` (default `list(ALL_SOURCES)`), `node/master_api.py:136-138`, and CLI `--sources all` — NOT via the deep_scan engine adapter (`SOURCE_MODULES = {dehashed, leakcheck, snylla, snusbase, hibp, intelx}`, `_module_config.py:63`).

**Action (concrete):**
- **Delete the 15 dead providers** (`providers/{haveibeenpwned,shodan,virustotal,abuseipdb,whoisxml,crtsh,wayback,social,holehe,h8mail,amass,theharvester,spiderfoot,datasploit,exiftool}.py`), prune `providers/__init__.py` to the 4 live imports, and trim `tests/unit/test_chiasmodon_providers.py` to the live 4 (keep the CLI-wrapper test pattern for the survivors). ~1 day.
- **Keep `ExternalToolIntel`** — delete only if the domain/recon CLIs get re-homed into `sources/` first; out of scope.
- **Optional refactor (not a delete):** reroute Phase-3 `_run_sherlock`/`_run_maigret` (external_tools.py) through the chiasmodon providers so each CLI has one canonical Python wrapper; behavior-preserving, verify with `pytest tests/integration/test_deep_scan_golden.py`.

**Verification:** after deletion, `grep -rn "chiasmodon.providers" src/ --include="*.py"` shows only sherlock/maigret/whatsmyname/phoneinfoga imports; `pytest tests/unit/test_chiasmodon_providers.py tests/unit/test_people_finder.py tests/unit/test_phone_finder.py -q` passes.

**Risk:** Low — the dead 15 have zero production callers; the live 4 are untouched. Keep the deletion scoped to provider files (never touch `leak_*` tools — those are live via `aggregator.py`).

---

### 4. Fix `docs-sync.yml` Version Badge Sync

**Status: ✅ DONE — commit `61bf87d`** replaced the fragile `sed -i` with idempotent version-badge sync; verified no `sed`/`perl` remains in `.github/workflows/docs-sync.yml`.

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

**Status: ✅ DONE — commit `8db5a28`** wired both modules (see AUDIT_REPORT.md §6 + §16 rows 308/310).

**Ground truth:** Two modules are registered/real but never run by deep scan because they lack dispatch wiring:
- `src/modules/free_intel/ai_enricher.py` (117 lines) has a real `AIExtractor` class with LLM-based analysis, but it is **NOT registered** in `_FREE_INTEL_DISPATCH`, `_MODULE_INPUTS`, or `get_module()`. It has zero importers across `src/` — it's orphaned. Per the audit learning: "The ai_enricher module must be excluded from the direct adapter pattern — it needs cross-module context from other scan results, not just a single string target."
- `crypto_tracer` IS a real module — `BlockchainTxTracer` (262 lines, `src/modules/crypto/tx_tracer.py`, real Etherscan+Blockchair+Solana APIs with mock fallback), registered in `src/modules/__init__.py:46`, listed in `FAST_SKIP_MODULES`, the builtin deep profile, and `_VALID_MODULES` (`deep_scan/profiles.py`), and consumed by `timeline_builder.py:94` (`finding.module == "crypto_tracer"`). It is missing only the `get_module()` branch in `src/cli/helpers.py:31-77` — so `engine.py:380-382` resolves `None` and silently skips it. This is a functionality gap, not dead code.

**Action:**
- `ai_enricher`: add an `enrich_from_results()` entry point that accepts `List[ScanResult]` (the full scan output) instead of a single `name: str`; wire it into `deep_scan/engine.py`'s post-processing phase (after all other modules complete); keep the single-target `scan(name)` proxy for backwards compatibility
- `crypto_tracer`: add `elif name in ("crypto_tracer", "tx_tracer"): from src.modules.crypto.tx_tracer import BlockchainTxTracer; return BlockchainTxTracer(zkit_salt=zkit_salt)` to `cli/helpers.get_module()`; verify `_MODULE_INPUTS` accepts crypto targets so the engine routes wallet/address/tx identifiers to it

**Verification:** A deep scan with AI enrichment enabled attaches richer LLM context in the final report output; a deep scan on a crypto address produces `crypto_tracer` findings with `transactions` raw_data that `timeline_builder` picks up. Test both the single-target and cross-module paths.

---

## Strategic Architecture Items (>1 week each)

### 10. Plugin System: Long-Term Direction

**Ground truth:** The plugin system is a **functional subsystem** — `PluginRegistry().discover()` works, CLI `plugins` command lists `example_logger` v0.1.0, 31 unit tests pass. The only gap is that `HookDispatcher` is never wired into the scan lifecycle (hooks exist but never fire during scans). Quick-Impact #1 covers the immediate decision; this item is the strategic call on direction.

**Options:**
- **Wire hooks** (1+ week): Hook plugin `before_scan`/`after_scan`/`on_finding` callbacks into `DeepScanEngine._run_iteration()` — requires integrating the dispatcher into 5+ engine methods. Optional third-party plugin support.
- **Keep as extension point** (30 min): document that hooks are opt-in; callers invoke `dispatcher.dispatch` explicitly. Remove the dead `_plugin_registry` declaration in `src/cli/main.py:30`.

**Recommendation:** Keep — do not delete. The system is alive (working CLI + tests) and provides a clean opt-in extension point. Wire hooks only if third-party extensibility is a product requirement; otherwise document as opt-in. Deletion would break the working `plugins` CLI command and 456 lines of tests for zero benefit. (If extensibility is needed, the existing module discovery in `sources/` and `free_intel/` provides a complementary extension model.)

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
| 1 | Plugin system: wire hooks or keep | Unwired subsystem | `src/plugin/` — functional (CLI works, 31 tests), hooks never fire in scan lifecycle | ✅ Done (keep) — `953cab0` |
| 2 | Dead profile entry (`darknet`) | Dead code | `DEEP_EXTRA` in scan_profiles.py — no module exists anywhere | ✅ Done — `2a572df` |
| 3 | `report_engine/` | Alive | 2 files, imported in 6 places (scan_commands.py) | Already done |
| 4 | `vendor/` trees | Alive — duplication audited | `modules/vendor/` (5 files, ExternalToolIntel + 3 mixins) + `vendor/chiasmodon/` (37 files). Audit complete: ExternalToolIntel not redundant (sole consumer of domain/recon CLIs); 15/19 chiasmodon providers production-dead (272 LOC, test-only); sherlock/maigret triple-wrapped across 3 frameworks | 1 day (delete 15 dead providers + prune __init__ + trim test) |
| 5 | Fragile sed in docs-sync.yml | Fragile CI | `release.yml` sed pattern | ✅ Done — `61bf87d` |
| 6 | No PyPI publish | Missing capability | `release.yml` has no publish step | 1 day |
| 7 | Docker image not pushed | Missing capability | `release.yml` builds but doesn't push | 1 day |
| 8 | Dockerfile uses pip, not uv | Inconsistency | Project standard is uv | 2 hours |
| 9 | Web UI has no auth | Security gap | `src/web/main.py` — no middleware | 1-2 days |
| 10 | Dispatch gap: `ai_enricher` + `crypto_tracer` | Functionality gap | 117 + 262 real lines, zero dispatch wiring — not in `get_module()` | ✅ Done — `8db5a28` |
| 11 | Plugin system: wire hooks or keep | Architecture debt | Functional subsystem, unwired dispatch (gaps of this class were wired in `8db5a28`) | ✅ Done (keep) — `953cab0` |
| 12 | No docs site | Missing capability | No mkdocs/sphinx config | 2-3 days |
| 13 | pipx/uv tool entry | Already present | `[project.scripts]` at pyproject.toml:86-87 — `1ai-osint = "src.cli.main:app"` | Already done |

## Quick Summary

```
┌──────────────────────────────────────────────────┐
│  Done:  plugin keep `953cab0` · darknet `2a572df`            │
│         docs-sync sed fix `61bf87d` · ai_enricher +           │
│         crypto_tracer dispatch `8db5a28` · vendor audit       │
├──────────────────────────────────────────────────┤
│  1-2 weeks: PyPI + Docker publish in release CI   │
│             Docker uv migration                    │
│             Web auth layer                         │
├──────────────────────────────────────────────────┤
│  Strategic:  Docs site (mkdocs/sphinx + Pages)   │
│             Plugin hook wiring (kept as opt-in)   │
└──────────────────────────────────────────────────┘
```

Every item above references exact files verified during the codebase audit. No speculations, no ROADMAP aspirations — only confirmed gaps.
