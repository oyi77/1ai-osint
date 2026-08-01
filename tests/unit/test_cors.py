"""CORS posture tests.

The API server answers CORS preflights for explicit local-dev origins (never
"*", so allow_credentials stays valid). The web UI app is served same-origin
and must NOT register CORS middleware at all.
"""

from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from src.api.app import _cors_origins, app
from src.web.app import create_app

_DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


class TestApiCors:
    def test_default_origins_explicit_dev(self):
        assert _cors_origins() == _DEV_ORIGINS

    def test_env_origins_override(self, monkeypatch):
        monkeypatch.setenv("AI_OSINT_CORS_ORIGINS", "https://a.example, https://b.example")
        assert _cors_origins() == ["https://a.example", "https://b.example"]

    def test_preflight_allows_dev_origin(self):
        client = TestClient(app)
        resp = client.options(
            "/api/scan",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "http://localhost:5173"

    def test_disallowed_origin_rejected(self):
        client = TestClient(app)
        resp = client.options(
            "/api/scan",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        # Starlette answers non-allowlisted preflights with 400 and never
        # echoes the origin — the browser sees no ACAO header.
        assert resp.status_code == 400
        assert "access-control-allow-origin" not in resp.headers


class TestWebNoCors:
    def test_web_app_has_no_cors_middleware(self):
        web = create_app()
        assert not any(m.cls is CORSMiddleware for m in web.user_middleware)
