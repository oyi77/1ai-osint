<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# routes

## Purpose
Web dashboard route handlers — HTTP endpoints for the investigation UI.

## Key Files
| File | Description |
|------|-------------|
| `dashboard.py` | Main dashboard view |
| `entities.py` | Entity browsing and search endpoints |
| `reports.py` | Report generation and viewing |
| `timeline.py` | Event timeline visualization endpoints |

## For AI Agents

### Working In This Directory
- Routes use FastAPI async patterns
- Templates rendered with Jinja2 from `src/web/templates/`

## Dependencies

### Internal
- `src/web/app.py` — FastAPI app instance
- `src/core/` — models and data access

<!-- MANUAL: -->
