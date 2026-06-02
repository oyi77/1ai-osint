<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# chiasmodon

## Purpose
Chiasmodon-based leak aggregation framework — wraps multiple breach/leak data sources behind a unified interface.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package exports |
| `base.py` | Base class for all leak sources |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `hibp/` | Have I Been Pwned integration |
| `leak_aggregator/` | Aggregates results from all sources |
| `leak_breachdirectory/` | BreachDirectory API integration |
| `leak_dehashed/` | DeHashed API integration |
| `leak_github/` | GitHub leak scanning |
| `leak_intelx/` | IntelX intelligence integration |
| `leak_leakcheck/` | LeakCheck API integration |
| `leak_pastebin/` | Pastebin scanning |
| `leak_reddit/` | Reddit scanning |
| `leak_scylla/` | Scylla.sh integration |
| `leak_snusbase/` | Snusbase integration |
| `leak_telegram/` | Telegram channel scanning |
| `providers/` | Shared provider utilities |
| `shodan/` | Shodan integration |

## For AI Agents

### Working In This Directory
- Each leak source is a separate subdirectory with its own implementation
- All sources inherit from `base.py`
- Free APIs only — no paid subscriptions
- Some sources may be rate-limited or unavailable

<!-- MANUAL: -->
