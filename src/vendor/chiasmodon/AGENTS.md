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
- **[Low]** `ChiasmodonTool` passes `check_token=False` to `Chiasmodon` (`chiasmodon/__init__.py:20`) — an invalid/missing `CHIASMODON_TOKEN` is never validated before queries
- **[Low]** `leak_github/__init__.py:10` reads `GITHUB_TOKEN` at class-definition (import) time, so missing credentials are only discovered on first use
- **[Medium]** `leak_telegram/__init__.py:51-59` uses deprecated `asyncio.get_event_loop()` and falls back to a `ThreadPoolExecutor` whose `pool.submit(...).result(timeout=120)` can block the caller for up to 120s

> Last updated: added frontmatter; corrected "Free APIs only" claim (DeHashed/Snusbase are commercial); added missing `chiasmodon/` subdirectory row; documented verified exports, env-based credentials, and per-source issues (commit 8fa2bbf)
