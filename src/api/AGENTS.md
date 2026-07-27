<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# api

## Purpose
FastAPI-based REST API layer — provides HTTP endpoints for queries, investigations, and system management.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | FastAPI application factory, middleware, and lifecycle |
| `__init__.py` | Package initializer |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `templates/` | Jinja2 HTML templates for API responses |

## For AI Agents

### Working In This Directory
- API follows async patterns throughout
- Routes are registered via `app.py`
- Health check at `GET /health`

## Dependencies

### Internal
- `src/core/` — models, config, database
- `src/modules/` — module invocations

<!-- MANUAL: -->
