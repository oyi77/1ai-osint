"""Tests for the optional bearer-token auth middleware in the 1ai-osint Web UI.

Run with: python -m pytest tests/unit/test_web_auth.py -v --tb=short
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _build_client() -> TestClient:
    """Create a FastAPI TestClient with a fresh app instance."""
    from src.web.app import create_app

    return TestClient(create_app())


class TestNoToken:
    """Without WEB_AUTH_TOKEN set, auth is disabled entirely."""

    def test_no_token_unset_allows_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WEB_AUTH_TOKEN", raising=False)
        client = _build_client()

        assert client.get("/").status_code == 200
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/stats").status_code == 200


class TestTokenBlocks:
    """With WEB_AUTH_TOKEN set, unauthenticated requests are rejected."""

    @pytest.fixture(autouse=True)
    def _set_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEB_AUTH_TOKEN", "secret")

    def test_token_blocks_unauthenticated(self) -> None:
        client = _build_client()

        assert client.get("/").status_code == 401
        assert client.get("/entities").status_code == 401
        assert client.get("/api/stats").status_code == 401
        assert client.get("/api/timeline/abc.json").status_code == 401
        assert client.get("/reports").status_code == 401

    def test_token_exempts_health(self) -> None:
        client = _build_client()

        response = client.get("/api/health")
        assert response.status_code == 200

    def test_token_exempts_static(self) -> None:
        client = _build_client()

        response = client.get("/static/anything.css")
        assert response.status_code != 401

    def test_token_grants_access(self) -> None:
        client = _build_client()

        response = client.get("/", headers={"Authorization": "Bearer secret"})
        assert response.status_code == 200

    def test_wrong_token_rejected(self) -> None:
        client = _build_client()

        response = client.get("/", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401

    def test_missing_scheme_rejected(self) -> None:
        client = _build_client()

        response = client.get("/", headers={"Authorization": "secret"})
        assert response.status_code == 401
