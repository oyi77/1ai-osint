---
scope: sources
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# sources

> Last updated: document 4 new keyless RE username sources and source_registry transport tiers, drop stale leak counts (commit 8fa2bbf)

## Purpose
Shared leak source scrapers. Each source produces `RawLeak` objects consumed by multiple modules (`crypto/leak_finder`, `data_leaks`). Also hosts 4 keyless regex-based username lookups (Hugging Face, Scratch, Itch.io, Codeforces) added in this commit.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `RawLeak` dataclass (line 11) and `BaseLeakSource` ABC (line 19) — `fetch_raw_leaks()` abstract, `search_for_address()` default `[]` |
| `__init__.py` | Auto-discovery via `discover_sources()` (line 18), exports `ALL_SOURCES` (line 43) |
| `huggingface_source.py` | `HuggingFaceSource` (line 40) — keyless, regex `^[a-z0-9][a-z0-9_-]{1,31}$` |
| `scratch_source.py` | `ScratchSource` (line 36) — keyless, regex `^[a-z0-9_-]{3,20}$` |
| `itchio_source.py` | `ItchIoSource` (line 38) — keyless, regex `^[a-z0-9_-]{2,32}$` |
| `codeforces_source.py` | `CodeforcesSource` (line 39) — keyless, regex `^[a-z0-9_-]{3,24}$`, uses the user.info API |
| `github_source.py` | GitHub code search + public gists |
| `reddit_source.py` | Reddit via pullpush.io API |
| `bitcointalk_source.py` | BitcoinTalk forum scraping |
| `paste_source.py` | Pastebin, dpaste, rentry |
| `twitter_source.py` | Twitter/X via twitter-cli |
| `telegram_source.py` | Telegram channels via Telethon |
| `duckduckgo_source.py` | DuckDuckGo HTML search |
| `gitlab_source.py` | GitLab public API + snippets |
| `npm_source.py` | NPM registry package scanning |
| `stackoverflow_source.py` | StackOverflow code snippets |
| `codeberg_source.py` | Codeberg (Gitea) code search |
| `chiasmodon_bridge.py` | Adapts chiasmodon OSINTTool sources to RawLeak |

## For AI Agents

### Working In This Directory
- Each source follows the `BaseLeakSource` ABC: `fetch_raw_leaks() -> list[RawLeak]`
- Optional `search_for_address(address) -> list[RawLeak]` for targeted search
- Auto-discovery: drop a `*_source.py` file with a class ending in `Source` (see `discover_sources()`)
- Transport taxonomy lives in `src/core/source_registry.py`: `TransportKind` (RE / SCRAPE / API / TOOL / LOCAL) with `transport_priority` (RE=0 < SCRAPE=1 < keyless API=2 < keyed API=3 < TOOL=4 < LOCAL=5); keyed-API sources read keys from env vars (e.g. `DEHASHED_API_KEY`, `LEAKCHECK_API_KEY`, `SCYLLA_API_KEY`, `HIBP_API_KEY`, `SHODAN_API_KEY`, `GITHUB_TOKEN`) — never hardcode values
- The 4 new sources are RE-tier username existence checks: `fetch_raw_leaks()` returns `[]`; `search_for_address()` returns 200/404 results and honors `request_delay`

### Testing Requirements
- Test each source independently
- Mock external APIs; patch HTTP clients (e.g. `httpx.AsyncClient`) at the source module path

<!-- MANUAL: -->
