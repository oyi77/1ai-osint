"""Integration tests for the FastAPI API endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.api.app import app


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client: httpx.AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "service" in data


@pytest.mark.asyncio
async def test_list_jobs(client: httpx.AsyncClient):
    resp = await client.get("/v1/jobs")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
@patch("src.api.app._run_job", new_callable=AsyncMock)
async def test_create_scan(mock_bg: AsyncMock, client: httpx.AsyncClient):
    resp = await client.post(
        "/api/scan",
        json={"target": "example.com", "fast": True, "max_iterations": 1},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    assert data["target"] == "example.com"


@pytest.mark.asyncio
async def test_docs(client: httpx.AsyncClient):
    resp = await client.get("/docs")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_openapi_schema(client: httpx.AsyncClient):
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    assert schema["info"]["title"] == "1ai-osint API"
    assert "/health" in schema["paths"]
    assert "/api/scan" in schema["paths"]
