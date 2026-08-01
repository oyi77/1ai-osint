"""Tests for the SSRF guard — scan targets must be validated before any fetch.

The deep-scan engine interpolates user-supplied targets into outbound HTTP
requests; without validation an operator could scan loopback, link-local, or
cloud-metadata addresses (``169.254.169.254``, ``127.0.0.1``, ...). These
tests pin the guard's contract: public IPs / unresolvable hostnames /
non-network identifiers are allowed; private and reserved hosts are blocked.

Run with: python -m pytest tests/unit/test_ssrf_guard.py -v --tb=short
"""

from __future__ import annotations

import ipaddress

import pytest

from src.core import ssrf_guard
from src.core.ssrf_guard import validate_scan_target


# Deterministic resolver stubs (avoid real DNS in tests).
def _unresolvable(host: str):
    return None


def _resolve_public(host: str):
    return [ipaddress.ip_address("8.8.8.8")]


def _resolve_private(host: str):
    return [ipaddress.ip_address("10.0.0.5")]


class TestBlockedIpLiterals:
    @pytest.mark.parametrize(
        "target",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.1.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "0.0.0.0",
            "2130706433",
            "0x7f000001",
            "017700000001",
        ],
    )
    def test_private_ip_literal_is_blocked(self, target: str) -> None:
        assert validate_scan_target(target) is False


class TestAllowedIpLiterals:
    @pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1", "134744072"])
    def test_public_ip_literal_is_allowed(self, target: str) -> None:
        assert validate_scan_target(target) is True


class TestBlockedHostnames:
    @pytest.mark.parametrize(
        "target",
        [
            "localhost",
            "localhost.localdomain",
            "metadata",
            "metadata.google.internal",
        ],
    )
    def test_blocked_hostname_is_rejected_without_dns(self, target: str) -> None:
        assert validate_scan_target(target) is False


class TestUrlForms:
    @pytest.mark.parametrize(
        "target",
        [
            "http://169.254.169.254/",
            "https://10.0.0.1/x",
            "http://[::1]:8080/path",
            "http://localhost:8000/",
            "http://user:pass@10.0.0.1/x",
        ],
    )
    def test_private_url_is_blocked(self, target: str) -> None:
        assert validate_scan_target(target) is False

    def test_public_ip_url_is_allowed(self) -> None:
        assert validate_scan_target("http://8.8.8.8/x") is True

    def test_public_hostname_url_is_allowed_when_unresolvable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ssrf_guard, "_resolve", _unresolvable)
        assert validate_scan_target("https://example.com/") is True


class TestHostnameResolution:
    @pytest.mark.parametrize(
        ("resolver", "expected"),
        [
            (_unresolvable, True),
            (_resolve_public, True),
            (_resolve_private, False),
        ],
    )
    def test_resolution_outcome(
        self,
        monkeypatch: pytest.MonkeyPatch,
        resolver,
        expected: bool,
    ) -> None:
        monkeypatch.setattr(ssrf_guard, "_resolve", resolver)
        assert validate_scan_target("example.com") is expected

    def test_host_with_port_allowed_when_unresolvable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ssrf_guard, "_resolve", _unresolvable)
        assert validate_scan_target("example.com:8080") is True


class TestNonNetworkTargets:
    @pytest.mark.parametrize(
        "target",
        [
            "alice",
            "+6281234567890",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "0x1234567890abcdef1234567890abcdef12345678",
        ],
    )
    def test_non_network_identifiers_are_allowed(self, target: str) -> None:
        assert validate_scan_target(target) is True

    @pytest.mark.parametrize("target", ["user@example.com", "user@gmail.com"])
    def test_email_with_public_domain_is_allowed(self, monkeypatch: pytest.MonkeyPatch, target: str) -> None:
        monkeypatch.setattr(ssrf_guard, "_resolve", _unresolvable)
        assert validate_scan_target(target) is True

    def test_email_with_private_ip_domain_is_blocked(self) -> None:
        assert validate_scan_target("user@10.0.0.1") is False


class TestNonString:
    @pytest.mark.parametrize("target", [None, "", "   ", 123])
    def test_non_string_or_blank_target_is_tolerated(self, target: object) -> None:
        assert validate_scan_target(target) is True


class TestApiIntegration:
    """End-to-end wiring: the API endpoints refuse private targets."""

    def test_react_scan_rejects_loopback(self) -> None:
        from unittest.mock import AsyncMock, patch

        from fastapi.testclient import TestClient

        from src.api.app import app

        with patch("src.api.app._run_job", new_callable=AsyncMock):
            client = TestClient(app)
            resp = client.post("/api/scan", json={"target": "127.0.0.1"})
        assert resp.status_code == 422

    def test_react_scan_allows_public_ip(self) -> None:
        from unittest.mock import AsyncMock, patch

        from fastapi.testclient import TestClient

        from src.api.app import app

        with patch("src.api.app._run_job", new_callable=AsyncMock):
            client = TestClient(app)
            resp = client.post("/api/scan", json={"target": "8.8.8.8"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "queued"

    def test_v1_scan_rejects_private_ip(self) -> None:
        from unittest.mock import AsyncMock, patch

        from fastapi.testclient import TestClient

        from src.api.app import app

        with patch("src.api.app._run_job", new_callable=AsyncMock):
            client = TestClient(app)
            resp = client.post("/v1/scan", json={"target": "10.0.0.1", "profile": "fast"})
        assert resp.status_code == 422

    def test_v1_scan_allows_fixture_target(self) -> None:
        from unittest.mock import AsyncMock, patch

        from fastapi.testclient import TestClient

        from src.api.app import app

        with patch("src.api.app._run_job", new_callable=AsyncMock):
            client = TestClient(app)
            resp = client.post("/v1/scan", json={"target": "fixture", "profile": "fast"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "queued"
