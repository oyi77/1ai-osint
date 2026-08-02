---
scope: social_osint
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# social_osint

> Last updated: correct line count (233) and stale "100+ platforms" claim (commit 8fa2bbf)

## Purpose
Social media OSINT — username search and availability checks across a fixed set of platforms, plus cross-platform identity correlation.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Full `SocialOSINTTool` implementation (233 lines) — platform search + username availability checks |

## For AI Agents

### Working In This Directory
- `PLATFORMS` covers 6 platforms: github, gitlab, reddit, twitter (via nitter.net), instagram, linkedin
- Direct httpx scrapes (no sherlock/whatsmyname/maigret delegation)
- `scan()` pivots a multi-word query through `src.modules.deep_scan.name_pivots.primary_username_for_name`
- Rate-limited: 60 RPM, burst 10
- All results feed into ZKIT identity correlation engine

## Dependencies

### Internal
- `src/core/` — models and config
- `src/modules/deep_scan/` — name-pivot to username helper
- `src/modules/identity_tracking/` — identity correlation

<!-- MANUAL: -->
