<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# leak_finder

## Purpose
Multi-source leak discovery engine. Coordinates scanning across 13 sources: GitHub, Reddit, BitcoinTalk, paste sites, Twitter, DuckDuckGo, GitLab, Telegram, NPM, StackOverflow, Codeberg, BreachDirectory (API key), and Shodan (API key).

## Key Files
| File | Description |
|------|-------------|
| `coordinator.py` | Main coordinator — orchestrates all leak sources |
| `extractor.py` | Extracts crypto keys/secrets from raw leak data |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `sources/` | Individual source scrapers (see `sources/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- **Hot path** — coordinator.py is the most-edited file
- Sources are pluggable — each implements a common interface
- Don't use `pushed:>date` GitHub filter (reduces key extraction from 39 to 4-5)
- Telegram: 30s timeout on client.start(), disconnect on failure, clean session lock files
- `run_once()` in `coordinator.py` inits its own sweeper (does not rely on `start()`)
- `extractor.py` skips test mnemonics (`_TEST_MNEMONICS`) and dedups via `KeyType`/bloom

### Testing Requirements
- Test each source independently
- Mock external APIs

> Last updated: documented coordinator/extractor behavior and `sources/` scrapers (commit 8fa2bbf)

<!-- MANUAL: -->
