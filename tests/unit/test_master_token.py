"""Tests for the master API token auth (fail-closed when a token is set)."""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from src.modules.node import db
from src.modules.node.master_api import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(db, "get_seen_keys_bloom", AsyncMock(return_value=b"a|b|c"))
    return TestClient(app)


def test_health_public(client):
    assert client.get("/api/health").status_code == 200


def test_missing_header_unauthorized(client, monkeypatch):
    monkeypatch.setenv("MASTER_API_TOKEN", "sekrit")
    assert client.get("/api/seen").status_code == 401


def test_wrong_bearer_unauthorized(client, monkeypatch):
    monkeypatch.setenv("MASTER_API_TOKEN", "sekrit")
    assert client.get("/api/seen", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_correct_bearer_ok(client, monkeypatch):
    monkeypatch.setenv("MASTER_API_TOKEN", "sekrit")
    assert client.get("/api/seen", headers={"Authorization": "Bearer sekrit"}).status_code == 200


def test_x_master_token_ok(client, monkeypatch):
    monkeypatch.setenv("MASTER_API_TOKEN", "sekrit")
    assert client.get("/api/seen", headers={"X-Master-Token": "sekrit"}).status_code == 200


def test_no_token_configured_open(client, monkeypatch):
    monkeypatch.delenv("MASTER_API_TOKEN", raising=False)
    assert client.get("/api/seen").status_code == 200


def test_empty_token_fail_closed(client, monkeypatch):
    monkeypatch.setenv("MASTER_API_TOKEN", "")
    assert client.get("/api/seen").status_code == 401
