<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# monitoring

## Purpose
Target watchlist and monitoring — continuous tracking of entities, change detection, and alerting.

## Key Files
| File | Description |
|------|-------------|
| `watchlist.py` | Target watchlist management — add, remove, list targets |
| `change_detector.py` | Detects changes in tracked entities across sources |
| `alerter.py` | Alert dispatch — Telegram, Slack, email, webhook |
| `models.py` | Monitoring-specific data models |
| `__init__.py` | Package initializer |

## For AI Agents

### Working In This Directory
- Watchlist supports persons, domains, IPs, usernames, emails
- Alerts support severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Change detection runs on scheduled intervals

## Dependencies

### Internal
- `src/core/` — models, database, config
- `src/modules/` — individual module scan results

<!-- MANUAL: -->
