---
scope: src/vendor/chiasmodon
depends_on: []
status: complete
---
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# chiasmodon

## Purpose
Chiasmodon-based leak aggregation framework — wraps multiple breach/leak data sources behind a unified interface.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package exports — `OSINTTool`, `ChiasmodonTool`, `OSINTAggregatorTool` |
| `base.py` | `OSINTTool` — base class defining `search`/`scan`/`analyze`/`learn` (raise `NotImplementedError`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `chiasmodon/` | Vendored Chiasmodon client — `pychiasmodon.py` (347 lines, class `Chiasmodon` at :228) + `ChiasmodonTool` wrapper |
| `hibp/` | Have I Been Pwned integration (`HIBPTool`) |
| `leak_aggregator/` | `LeakAggregatorTool` — aggregates results from all sources |
| `leak_breachdirectory/` | BreachDirectory API integration (`BreachDirectoryTool`) |
| `leak_dehashed/` | DeHashed API integration (`DeHashedTool`, `api.dehashed.com` — commercial) |
| `leak_github/` | GitHub leak scanning (`GithubDorkTool`, env `GITHUB_TOKEN`) |
| `leak_intelx/` | IntelX intelligence integration (`IntelXTool`, env `INTELX_API_KEY`) |
| `leak_leakcheck/` | LeakCheck API integration (`LeakCheckTool`) |
| `leak_pastebin/` | Pastebin scanning (`PastebinTool`) |
| `leak_reddit/` | Reddit scanning (`RedditLeakTool`) |
| `leak_scylla/` | Scylla.sh integration (`ScyllaTool`, env `SCYLLA_API_KEY`) |
| `leak_snusbase/` | Snusbase integration (`SnusbaseTool`, env `SNUSBASE_API_KEY`, `api.snusbase.com` — commercial) |
| `leak_telegram/` | Telegram channel scanning (`TelegramLeakTool`, env `TELEGRAM_BOT_TOKEN`) |
| `providers/` | Shared provider utilities (`MaigretProvider`, `PhoneInfogaProvider`, `SherlockProvider`, `WhatsMyNameProvider`) |
| `shodan/` | Shodan integration (`ShodanTool`) |

## For AI Agents

### Working In This Directory
- Each leak source is a separate subdirectory implementing `OSINTTool`; `ChiasmodonTool` (name `chiasmodon`, env `CHIASMODON_TOKEN`) and `OSINTAggregatorTool` (wraps `LeakAggregatorTool`) live in `chiasmodon/__init__.py`
- **Not** "free APIs only": DeHashed (`api.dehashed.com`) and Snusbase (`api.snusbase.com`) are commercial paid services (corrected from the previous claim)
- All credentials are read from `os.environ` at runtime — no hardcoded secrets in the vendored sources

## Known Issues

### Issues
- **[RESOLVED-Low]** `ChiasmodonTool` passes `check_token=False` to `Chiasmodon` (`chiasmodon/__init__.py:20`) — `check_token` now defaults to `True` (`chiasmodon/__init__.py:26`), and a missing `CHIASMODON_TOKEN` returns an explicit error dict (`chiasmodon/__init__.py:17-22`) before any query
- **[RESOLVED-Low]** `leak_github/__init__.py:10` reads `GITHUB_TOKEN` at class-definition (import) time — token is now read lazily via `os.environ.get("GITHUB_TOKEN")` at call time (`leak_github/__init__.py:14`), with a missing token returning an explicit error dict
- **[RESOLVED-Medium]** `leak_telegram/__init__.py:51-59` uses deprecated `asyncio.get_event_loop()` and falls back to a `ThreadPoolExecutor` whose `pool.submit(...).result(timeout=120)` can block the caller for up to 120s — now loop-safe: `get_running_loop()` try/except (`leak_telegram/__init__.py:54-58`), `asyncio.run` fallback when no loop is running (`:58`), and `asyncio.wait_for(..., timeout=120)` bounds the scan (`:52`)

> Last updated: added frontmatter; corrected "Free APIs only" claim (DeHashed/Snusbase are commercial); added missing `chiasmodon/` subdirectory row; documented verified exports, env-based credentials, and per-source issues (commit 8fa2bbf)
> Last updated: fix pass — ChiasmodonTool `check_token` defaults True (`chiasmodon/__init__.py:26`) + missing-token error dict (`:17-22`), leak_github lazy `GITHUB_TOKEN` read (`:14`), leak_telegram loop-safe (`get_running_loop` + `asyncio.run`, `:54-58`)
