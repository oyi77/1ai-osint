"""Auth fail-closed / least-privilege fallback tests.

Covers the hardened auth posture shipped in the auth hardening pass:

* ``REQUIRE_AUTH_TOKENS=1`` turns the API and web factories fail-closed:
  every non-exempt route returns 401 without a valid bearer token.
* Without the flag, the default posture is fail-open but *least-privilege*:
  requests are threaded into the engine with ``AccessTier.READONLY`` instead
  of the old ``ADMIN`` fallback.
* ``WEB_AUTH_TOKENS`` / legacy ``WEB_AUTH_TOKEN`` map bearer tokens to tiers,
  and the tier actually reaches the engine job.

The API middleware is attached at import time, so these tests reload
``src.api.app`` after mutating the environment. The web factory reads the
environment at call time, so it needs no reload.
"""

from __future__ import annotations

import importlib
import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import src.api.app as api_module
from src.core.rbac import AccessTier
from src.web.app import create_app

_AUTH_ENV_VARS = ("WEB_AUTH_TOKEN", "WEB_AUTH_TOKENS", "REQUIRE_AUTH_TOKENS")


@pytest.fixture(autouse=True)
def _reset_api_module():
    """Restore a clean module state after each test.

    Autouse fixtures are torn down last (same scope), so this runs after
    monkeypatch's own teardown and guarantees the final state is deterministic
    regardless of which test mutated the environment.
    """
    yield
    for var in _AUTH_ENV_VARS:
        os.environ.pop(var, None)
    importlib.reload(api_module)


def _reload_api_with(**env) -> TestClient:
    """Set auth env vars, reload the API module, return a test client."""
    for var in _AUTH_ENV_VARS:
        os.environ.pop(var, None)
    for key, value in env.items():
        os.environ[key] = value
    importlib.reload(api_module)
    return TestClient(api_module.app)


def test_fail_closed_flag_rejects_unauthenticated_api():
    client = _reload_api_with(REQUIRE_AUTH_TOKENS="1")
    # Exempt paths stay reachable.
    assert client.get("/health").status_code == 200
    assert client.get("/ui").status_code == 200
    assert client.get("/").status_code == 200
    # Non-exempt routes are locked down without a token.
    assert client.get("/v1/jobs").status_code == 401
    assert client.post("/v1/scan", json={"target": "x"}).status_code == 401


def test_fail_open_default_threads_readonly():
    client = _reload_api_with()
    with patch("src.api.app._run_job", new_callable=AsyncMock) as mock_run:
        resp = client.post("/v1/scan", json={"target": "fixture", "profile": "fast"})
    assert resp.status_code == 200
    mock_run.assert_awaited()
    # Plain TestClient scope has no auth_tier → READONLY least-privilege
    # fallback must be threaded through to the engine.
    # Compare by value, not identity: test_rbac_tos.py reloads src.core.rbac
    # (importlib.reload for env-var override tests), which creates a *new*
    # AccessTier class in sys.modules while src.api.app still holds the old
    # one — cross-class `is` fails even though both are the same tier.
    tier = mock_run.await_args.kwargs["requester_tier"]
    assert tier == AccessTier.READONLY
    assert int(tier) == int(AccessTier.READONLY)  # 10 — READONLY


def test_bearer_tokens_thread_tier_and_reject_unknown():
    client = _reload_api_with(WEB_AUTH_TOKENS="admin:sekret,readonly:rtok")
    with patch("src.api.app._run_job", new_callable=AsyncMock) as mock_run:
        admin = client.post(
            "/v1/scan",
            json={"target": "fixture", "profile": "fast"},
            headers={"Authorization": "Bearer sekret"},
        )
        assert admin.status_code == 200
        tier = mock_run.await_args.kwargs["requester_tier"]
        assert int(tier) == int(AccessTier.ADMIN)  # 30

    with patch("src.api.app._run_job", new_callable=AsyncMock) as mock_run:
        ro = client.post(
            "/v1/scan",
            json={"target": "fixture", "profile": "fast"},
            headers={"Authorization": "Bearer rtok"},
        )
        assert ro.status_code == 200
        tier = mock_run.await_args.kwargs["requester_tier"]
        assert int(tier) == int(AccessTier.READONLY)  # 10

    # Unknown token → 401, even with auth configured.
    assert (
        client.post(
            "/v1/scan",
            json={"target": "fixture", "profile": "fast"},
            headers={"Authorization": "Bearer nope"},
        ).status_code
        == 401
    )
    # Exempt health probe unaffected by auth config.
    assert client.get("/health").status_code == 200


def test_legacy_single_token_maps_to_admin():
    client = _reload_api_with(WEB_AUTH_TOKEN="legacy-secret")
    with patch("src.api.app._run_job", new_callable=AsyncMock) as mock_run:
        resp = client.post(
            "/v1/scan",
            json={"target": "fixture", "profile": "fast"},
            headers={"Authorization": "Bearer legacy-secret"},
        )
    assert resp.status_code == 200
    tier = mock_run.await_args.kwargs["requester_tier"]
    assert int(tier) == int(AccessTier.ADMIN)  # 30 — legacy token maps to ADMIN


def test_web_factory_fail_closed(monkeypatch):
    for var in _AUTH_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("REQUIRE_AUTH_TOKENS", "1")
    client = TestClient(create_app())
    assert client.get("/api/health").status_code == 200  # exempt
    assert client.get("/api/auth/tier").status_code == 401  # non-exempt probe


def test_web_factory_default_open(monkeypatch):
    for var in _AUTH_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    client = TestClient(create_app())
    resp = client.get("/api/auth/tier")
    assert resp.status_code == 200
    assert resp.json()["tier"] == "READONLY"
    assert resp.json()["rank"] == int(AccessTier.READONLY)
