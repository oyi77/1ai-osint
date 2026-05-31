<!-- Parent: ../AGENTS.md -->

# sources

## Purpose
Shared leak source scrapers. Each source produces `RawLeak` objects consumed by multiple modules (`crypto/leak_finder`, `data_leaks`).

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `RawLeak` dataclass and `BaseLeakSource` ABC |
| `__init__.py` | Auto-discovery via `discover_sources()`, exports `ALL_SOURCES` |
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
- Auto-discovery: drop a `*_source.py` file with a class ending in `Source`
- All sources import `RawLeak` from `src.modules.sources.base`
- Leak counts (from old location): GitHub 1904, Reddit 1865, BitcoinTalk 121, paste 9, Twitter 24, DuckDuckGo 4, GitLab 0

### Testing Requirements
- Test each source independently
- Mock external APIs
- Mock patch path: `src.modules.sources.<source_name>.httpx.AsyncClient`
