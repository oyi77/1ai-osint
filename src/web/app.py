"""FastAPI application factory for 1ai-osint Web UI."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

HERE = Path(__file__).parent


class AuthMiddleware:
    """Optional bearer-token gate for the Web UI.

    Enabled only when ``WEB_AUTH_TOKEN`` is set at app creation time. When
    enabled, every HTTP request is rejected with ``401`` unless it carries an
    ``Authorization: Bearer <token>`` header or targets an exempt path
    (``/static/*`` static assets and the ``/api/health`` health check). The
    token comparison uses :func:`secrets.compare_digest` (timing-safe).
    """

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or self._is_authorized(scope):
            await self.app(scope, receive, send)
            return
        response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
        await response(scope, receive, send)

    def _is_authorized(self, scope) -> bool:
        path = scope.get("path", "")
        if path == "/api/health" or path.startswith("/static"):
            return True
        for key, value in scope.get("headers", []):
            if key.lower() == b"authorization":
                scheme, _, token = value.decode("latin-1").partition(" ")
                return scheme.lower() == "bearer" and secrets.compare_digest(token, self.token)
        return False


def create_app() -> FastAPI:
    """Create and configure the 1ai-osint Web UI application."""
    app = FastAPI(title="1ai-osint Web UI")

    # Import routes here to avoid circular imports at module level
    from src.web.routes.api import router as api_router
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
    app.include_router(api_router)

    # Optional bearer-token auth — enabled when WEB_AUTH_TOKEN is set.
    token = os.environ.get("WEB_AUTH_TOKEN", "").strip()
    if token:
        app.add_middleware(AuthMiddleware, token=token)

    return app
