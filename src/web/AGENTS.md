<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# web

## Purpose
Web dashboard — FastAPI-based frontend with routes, templates, and static assets for the investigation UI.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | FastAPI web app initialization |
| `main.py` | Web UI entry point |
| `__init__.py` | Package initializer |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `routes/` | Web route handlers — dashboard, entities, reports, timeline (see `routes/AGENTS.md`) |
| `static/` | Static assets (CSS, JS, images) |
| `templates/` | Jinja2 HTML templates |

## For AI Agents

### Working In This Directory
- Uses FastAPI + Jinja2 templates
- Routes are async throughout

<!-- MANUAL: -->
