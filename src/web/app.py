"""FastAPI application factory for 1ai-osint Web UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

HERE = Path(__file__).parent


def create_app() -> FastAPI:
    """Create and configure the 1ai-osint Web UI application."""
    app = FastAPI(title="1ai-osint Web UI")

    # Import routes here to avoid circular imports at module level
    from src.web.routes.dashboard import router as dashboard_router
    from src.web.routes.entities import router as entities_router
    from src.web.routes.reports import router as reports_router
    from src.web.routes.timeline import router as timeline_router

    # Mount static files
    static_dir = HERE / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routers
    app.include_router(dashboard_router)
    app.include_router(entities_router)
    app.include_router(reports_router)
    app.include_router(timeline_router)

    return app
