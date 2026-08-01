"""Inbound request limiter tests for the scan-creation endpoints.

Verifies that the per-client ``RequestLimiter`` gate (``_api_limiter``) blocks
a client that exceeds its burst quota with 429 + Retry-After, while health and
read endpoints stay reachable. The limiter is monkeypatched to a tiny quota so
the test is deterministic and never interferes with the shared default.
"""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import src.api.app as api_app
from src.core.rate_limiter import RequestLimiter


def _client() -> TestClient:
    return TestClient(api_app.app)


def test_scan_creation_is_rate_limited(monkeypatch):
    monkeypatch.setattr(api_app, "_api_limiter", RequestLimiter(requests_per_minute=1, burst=1))
    client = _client()
    with patch("src.api.app._run_job", new_callable=AsyncMock):
        first = client.post("/v1/scan", json={"target": "fixture", "profile": "fast"})
        second = client.post("/v1/scan", json={"target": "fixture", "profile": "fast"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers.get("retry-after") == "60"  # 1 rpm → one token per 60s
    assert "rate limit" in second.json()["detail"].lower()


def test_react_scan_endpoint_is_rate_limited(monkeypatch):
    monkeypatch.setattr(api_app, "_api_limiter", RequestLimiter(requests_per_minute=1, burst=1))
    client = _client()
    with patch("src.api.app._run_job", new_callable=AsyncMock):
        first = client.post("/api/scan", json={"target": "fixture", "fast": True})
        second = client.post("/api/scan", json={"target": "fixture", "fast": True})
    assert first.status_code == 200
    assert second.status_code == 429


def test_health_and_reads_unaffected_by_tight_limiter(monkeypatch):
    monkeypatch.setattr(api_app, "_api_limiter", RequestLimiter(requests_per_minute=1, burst=1))
    client = _client()
    assert client.get("/health").status_code == 200
    assert client.get("/v1/jobs").status_code == 200
    # The single token is consumed only by scan creation, so reads stay open.
    with patch("src.api.app._run_job", new_callable=AsyncMock):
        assert client.post("/v1/scan", json={"target": "fixture", "profile": "fast"}).status_code == 200
        assert client.post("/v1/scan", json={"target": "fixture", "profile": "fast"}).status_code == 429
    assert client.get("/health").status_code == 200


def test_bucket_recovers_after_refill(monkeypatch):
    monkeypatch.setattr(api_app, "_api_limiter", RequestLimiter(requests_per_minute=1, burst=1))
    client = _client()
    with patch("src.api.app._run_job", new_callable=AsyncMock):
        assert client.post("/v1/scan", json={"target": "fixture", "profile": "fast"}).status_code == 200
        assert client.post("/v1/scan", json={"target": "fixture", "profile": "fast"}).status_code == 429
        # Backdate the client's bucket so a refill has accrued (1 rpm → 60s
        # per token); deterministic, no clock monkeypatch, no sleep.
        assert "testclient" in api_app._api_limiter._buckets
        tokens, last = api_app._api_limiter._buckets["testclient"]
        api_app._api_limiter._buckets["testclient"] = (tokens, last - 61.0)
        assert client.post("/v1/scan", json={"target": "fixture", "profile": "fast"}).status_code == 200


def test_limiter_allow_and_reset():
    limiter = RequestLimiter(requests_per_minute=60, burst=2)
    assert limiter.allow("a")
    assert limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")  # separate key unaffected
    limiter.reset("a")
    assert limiter.allow("a")
    assert limiter.allow("a")  # fresh bucket holds burst=2 again
    assert not limiter.allow("a")
    limiter.reset()
    assert limiter.allow("a")
    assert limiter.allow("b")
