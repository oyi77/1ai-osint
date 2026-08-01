"""FastAPI application factory for 1ai-osint Web UI."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

load_dotenv()

from src.core.rbac import AccessTier  # noqa: E402

HERE = Path(__file__).parent


class AuthMiddleware:
    """Bearer-token gate with per-tier RBAC + optional JWT sessions (Layer 3).

    Enabled only when ``WEB_AUTH_TOKEN`` (legacy, treated as ADMIN) or
    ``WEB_AUTH_TOKENS`` (``tier:token,tier:token``) is set at app creation.
    When enabled, every HTTP request is rejected with ``401`` unless it
    carries an ``Authorization: Bearer *** header or targets an exempt path
    (``/static/*`` static assets, ``/api/health``, and ``/api/auth/login``).
    Bearer tokens may be either static tier tokens (timing-safe comparison)
    or JWT session tokens minted by ``/api/auth/login`` (verified signature +
    expiry, tier read from the ``tier`` claim). The resolved access tier is
    stored in ``scope["auth_tier"]`` so route handlers can enforce
    source-level RBAC.
    """

    def __init__(self, app, token: str | None = None, tokens: dict[str, AccessTier] | None = None):
        self.app = app
        self._token = token
        self._tokens = tokens or {}

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or self._is_authorized(scope):
            await self.app(scope, receive, send)
            return
        response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
        await response(scope, receive, send)

    def _is_authorized(self, scope) -> bool:
        path = scope.get("path", "")
        if path == "/api/health" or path.startswith("/static") or path == "/api/auth/login":
            return True
        for key, value in scope.get("headers", []):
            if key.lower() == b"authorization":
                scheme, _, token = value.decode("latin-1").partition(" ")
                if scheme.lower() != "bearer" or not token:
                    return False
                if self._token is not None and secrets.compare_digest(token, self._token):
                    scope["auth_tier"] = AccessTier.ADMIN
                    return True
                tier = self._tokens.get(token)
                if tier is not None:
                    scope["auth_tier"] = tier
                    return True
                # JWT session token fallback
                from src.web.auth import verify_token

                jwt_tier = verify_token(token)
                if jwt_tier is not None:
                    scope["auth_tier"] = jwt_tier
                    return True
                return False
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

    # Optional bearer-token auth — enabled when a token is configured.
    # Legacy single token (WEB_AUTH_TOKEN) → ADMIN; multi-tier via
    # WEB_AUTH_TOKENS = "readonly:tok1,admin:tok2". Re-read at app creation
    # so runtime config is honored.
    from src.core.rbac import tiers_from_env

    tokens = tiers_from_env()
    if tokens:
        app.add_middleware(
            AuthMiddleware,
            token=os.environ.get("WEB_AUTH_TOKEN", "").strip() or None,
            tokens=tokens,
        )

    return app
