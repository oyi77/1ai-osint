---
scope: monitoring
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# monitoring

> Last updated: correct stale multi-channel alert claim — only Console/File alerters exist (commit 8fa2bbf)

## Purpose
Target watchlist and monitoring — continuous tracking of entities, change detection, and alerting.

## Key Files
| File | Description |
|------|-------------|
| `watchlist.py` | `WatchlistManager` (line 17) — target watchlist management, add/remove/list targets |
| `change_detector.py` | `ChangeDetector` (line 22) — detects changes in tracked entities across sources |
| `alerter.py` | `BaseAlerter` ABC (line 20), `ConsoleAlerter` (line 86), `FileAlerter` (line 94, JSONL under `investigations/watchlist/alerts`), `AlertDispatcher` (line 128) |
| `models.py` | `ChangeType`, `ChangeSeverity`, `WatchlistTarget`, `ChangeEvent`, `AlertRule` |
| `__init__.py` | Exports the 10 public symbols listed in `__all__` (line 24) |

## For AI Agents

### Working In This Directory
- Watchlist supports persons, domains, IPs, usernames, emails
- Alerts support severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Only Console + File alerters are implemented today; "multi-channel" is pluggable via `AlertDispatcher.register_channel` (Telegram/Slack/email/webhook adapters are not present)
- Change detection runs on scheduled intervals; `ChangeDetector` keys on `_RISK_TRIGGER_FIELDS`

## Dependencies

### Internal
- `src/core/` — models, database, config
- `src/modules/` — individual module scan results

<!-- MANUAL: -->
