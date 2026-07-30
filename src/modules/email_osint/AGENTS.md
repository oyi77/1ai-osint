<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# email_osint

## Purpose
Email OSINT — email validation, breach database lookup, and associated account discovery.

## Key Files
| File | Description |
||------|-------------|
|| `__init__.py` | Full `EmailOSINTTool` implementation (246 lines) — breach lookup, email validation, account discovery |

## For AI Agents

### Working In This Directory
|- **Full implementation** — `EmailOSINTTool` class with breach database lookup, email validation, and associated account discovery
|- Checks emails against known breach databases (DeHashed, HIBP-style via Chiasmodon)
|- Validates email deliverability and format
|- Results feed into ZKIT identity correlation|

## Dependencies

### Internal
- `src/core/` — models and config
- `src/vendor/chiasmodon/` — breach data sources

<!-- MANUAL: -->
