"""Tests for Layer-3 completion: plugin hook wiring, module install subcommand,
JWT sessions, and per-route tier enforcement.

Run with: python -m pytest tests/unit/test_layer3_web_plugins.py -v --tb=short
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Plugin hook wiring (roadmap 5.1: "Hook system ... never wired")
# ---------------------------------------------------------------------------


class _RecordingPlugin:
    """Minimal BasePlugin-compatible spy used to prove hooks fire."""

    name = "spy-plugin"
    version = "0.0.1"
    description = "test spy"
    hooks = ["on_scan_start", "on_scan_end", "on_error"]
    calls: list[str] = []

    async def on_scan_start(self, target: str, module: str) -> None:
        self.calls.append(f"start:{target}:{module}")

    async def on_scan_end(self, result) -> None:
        self.calls.append(f"end:{getattr(result, 'target', '?')}")

    async def on_error(self, error, context: dict) -> None:
        self.calls.append(f"error:{context.get('target')}")


class TestHookWiring:
    """Prove the engine fires plugin hooks at the right lifecycle points."""

    @pytest.fixture(autouse=True)
    def _register_spy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.plugin import get_dispatcher, reset_plugins

        # Give the engine a dispatcher that already knows our spy plugin.
        registry = get_dispatcher()._registry  # type: ignore[attr-defined]
        spy = _RecordingPlugin()
        spy.calls = []
        registry._plugins["spy-plugin"] = spy  # type: ignore[attr-defined]
        self._spy = spy
        yield
        reset_plugins()

    async def test_engine_fires_start_and_end_hooks(self) -> None:
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(fast=True, max_iterations=1, max_targets_per_iteration=2)
        result = await engine.scan("test@example.com")
        assert result is not None
        assert any(c.startswith("start:test@example.com:deep_scan") for c in self._spy.calls)
        assert any(c.startswith("end:test@example.com") for c in self._spy.calls)

    async def test_engine_fires_error_hook(self) -> None:
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(fast=True, max_iterations=1, max_targets_per_iteration=2)
        # Force a failure in the scan body

        def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

        engine._detect_identifier = boom  # type: ignore[attr-defined]
        result = await engine.scan("x@y.z")
        assert any(c.startswith("error:x@y.z") for c in self._spy.calls)
        assert result.errors  # error recorded on the result


class TestPluginRegistryEntryPoints:
    """The 1ai_osint.plugins entry-point group resolves (roadmap 5.1 [~])."""

    def test_entry_point_group_declared(self) -> None:
        from pathlib import Path

        import tomllib

        root = Path(__file__).resolve().parents[2]
        pyproject = tomllib.loads((root / "pyproject.toml").read_text())
        eps = pyproject["project"]["entry-points"]
        assert "1ai_osint.plugins" in eps

    def test_install_subcommand_registered(self) -> None:
        from src.cli.commands.config_commands import install

        assert callable(install)


class TestInstallSubcommand:
    """osint install: pip-installs a plugin package and re-discovers it."""

    def test_install_help_text(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "src.cli.main", "install", "--help"],
            capture_output=True,
            text=True,
            cwd=os.getcwd(),
        )
        assert result.returncode == 0
        assert "Install a plugin package" in result.stdout

    def test_install_unknown_package_fails_cleanly(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.cli.main",
                "install",
                "1ai-osint-plugin-definitely-not-real-xyz",
            ],
            capture_output=True,
            text=True,
            cwd=os.getcwd(),
            timeout=120,
        )
        # pip fails (or times out on network) — must not crash with a traceback
        assert result.returncode != 0
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# JWT sessions (roadmap: web auth upgrade)
# ---------------------------------------------------------------------------


class TestJWTLogin:
    """/api/auth/login exchanges a static token for a JWT session token."""

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEB_AUTH_TOKENS", "readonly:ro-secret,admin:admin-secret")
        monkeypatch.setenv("JWT_SECRET", "test-secret-key")

    def _client(self) -> TestClient:
        from src.web.app import create_app

        return TestClient(create_app())

    def test_login_disabled_without_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("JWT_SECRET", raising=False)
        client = self._client()
        resp = client.post("/api/auth/login", json={"token": "admin-secret"})
        assert resp.status_code == 410

    def test_login_valid_token_returns_jwt(self) -> None:
        client = self._client()
        resp = client.post("/api/auth/login", json={"token": "admin-secret"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["tier"] == "admin"
        assert body["token_type"] == "bearer"
        assert body["access_token"].count(".") == 2  # JWT shape

    def test_login_invalid_token_rejected(self) -> None:
        client = self._client()
        resp = client.post("/api/auth/login", json={"token": "wrong"})
        assert resp.status_code == 401

    def test_jwt_grants_access(self) -> None:
        client = self._client()
        token = client.post("/api/auth/login", json={"token": "admin-secret"}).json()["access_token"]
        resp = client.get("/", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_jwt_carries_correct_tier(self) -> None:
        client = self._client()
        body = client.post("/api/auth/login", json={"token": "ro-secret"}).json()
        assert body["tier"] == "readonly"
        resp = client.get("/api/auth/tier", headers={"Authorization": f"Bearer {body['access_token']}"})
        assert resp.status_code == 200
        assert resp.json()["tier"] == "READONLY"

    def test_tampered_jwt_rejected(self) -> None:
        client = self._client()
        token = client.post("/api/auth/login", json={"token": "admin-secret"}).json()["access_token"]
        tampered = token[:-2] + ("ab" if token[-2:] != "ab" else "cd")
        resp = client.get("/", headers={"Authorization": f"Bearer {tampered}"})
        assert resp.status_code == 401


class TestRequireTier:
    """Per-route tier enforcement (require_tier dependency)."""

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEB_AUTH_TOKENS", "readonly:ro-secret,analyst:an-secret,admin:admin-secret")

    def _client(self) -> TestClient:
        from src.web.app import create_app

        return TestClient(create_app())

    def test_analyst_route_blocks_readonly(self) -> None:
        client = self._client()
        resp = client.get("/api/search", params={"q": "test"}, headers={"Authorization": "Bearer ro-secret"})
        assert resp.status_code == 403

    def test_analyst_route_allows_analyst(self) -> None:
        client = self._client()
        resp = client.get("/api/search", params={"q": "test"}, headers={"Authorization": "Bearer an-secret"})
        assert resp.status_code == 200

    def test_admin_allowed(self) -> None:
        client = self._client()
        resp = client.get("/api/search", params={"q": "test"}, headers={"Authorization": "Bearer admin-secret"})
        assert resp.status_code == 200

    def test_unauthenticated_still_401(self) -> None:
        client = self._client()
        resp = client.get("/api/search", params={"q": "test"})
        assert resp.status_code == 401
