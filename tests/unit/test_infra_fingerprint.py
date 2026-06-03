"""Tests for Phase 5 Pillar 5: Infrastructure Fingerprinting Engine."""

from __future__ import annotations
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from src.modules.domain_recon.infra_fingerprint import (
    InfraFingerprintEngine,
    InfraFingerprint,
)


@pytest.fixture
def engine():
    return InfraFingerprintEngine()


def test_simple_hash_deterministic(engine):
    data = b"hello world"
    h1 = engine._simple_hash(data)
    h2 = engine._simple_hash(data)
    assert h1 == h2
    assert isinstance(h1, int)


def test_simple_hash_different_inputs(engine):
    h1 = engine._simple_hash(b"domain_a")
    h2 = engine._simple_hash(b"domain_b")
    assert h1 != h2


def test_extract_cert_sans_empty(engine):
    cert = {"subjectAltName": []}
    sans = engine._extract_cert_sans(cert)
    assert sans == []


def test_extract_cert_sans_populated(engine):
    cert = {
        "subjectAltName": [
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
            ("IP Address", "1.2.3.4"),
        ]
    }
    sans = engine._extract_cert_sans(cert)
    assert "example.com" in sans
    assert "www.example.com" in sans
    assert "1.2.3.4" not in sans  # Only DNS entries


def test_extract_cert_field_cn(engine):
    cert = {"issuer": [[("commonName", "Let's Encrypt Authority X3")]]}
    result = engine._extract_cert_field(cert, "issuer")
    assert "Let's Encrypt" in result


def test_extract_cert_field_missing(engine):
    result = engine._extract_cert_field({}, "issuer")
    assert result == ""


def test_resolve_domain_returns_list(engine):
    with patch(
        "socket.getaddrinfo",
        return_value=[
            (None, None, None, None, ("1.2.3.4", 0)),
            (None, None, None, None, ("5.6.7.8", 0)),
        ],
    ):
        ips = engine._resolve_domain("example.com")
    assert isinstance(ips, list)
    assert "1.2.3.4" in ips


def test_resolve_domain_error_returns_empty(engine):
    import socket

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("fail")):
        ips = engine._resolve_domain("nonexistent.invalid")
    assert ips == []


@pytest.mark.asyncio
async def test_fetch_favicon_hash_success(engine):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"<svg>favicon</svg>"
    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_client
        result = await engine._fetch_favicon_hash("example.com")
    assert isinstance(result, int)


@pytest.mark.asyncio
async def test_fetch_favicon_hash_not_found(engine):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.content = b""
    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_client
        result = await engine._fetch_favicon_hash("example.com")
    assert result is None


@pytest.mark.asyncio
async def test_correlate_by_tls_cert(engine):
    fps = [
        InfraFingerprint(domain="a.com", tls_cert_sha256="abc123"),
        InfraFingerprint(domain="b.com", tls_cert_sha256="abc123"),
        InfraFingerprint(domain="c.com", tls_cert_sha256="def456"),
    ]
    clusters = await engine.correlate_infrastructure(fps)
    tls_clusters = [c for c in clusters if c.shared_attribute == "tls_cert"]
    assert len(tls_clusters) == 1
    assert set(tls_clusters[0].domains) == {"a.com", "b.com"}


@pytest.mark.asyncio
async def test_correlate_by_favicon(engine):
    fps = [
        InfraFingerprint(domain="x.com", favicon_hash=12345),
        InfraFingerprint(domain="y.com", favicon_hash=12345),
    ]
    clusters = await engine.correlate_infrastructure(fps)
    fav_clusters = [c for c in clusters if c.shared_attribute == "favicon"]
    assert len(fav_clusters) == 1


@pytest.mark.asyncio
async def test_correlate_empty(engine):
    clusters = await engine.correlate_infrastructure([])
    assert clusters == []


@pytest.mark.asyncio
async def test_correlate_by_nameserver(engine):
    fps = [
        InfraFingerprint(
            domain="a.com", nameservers=["ns1.cloudflare.com", "ns2.cloudflare.com"]
        ),
        InfraFingerprint(domain="b.com", nameservers=["ns1.cloudflare.com"]),
    ]
    clusters = await engine.correlate_infrastructure(fps)
    ns_clusters = [c for c in clusters if c.shared_attribute == "nameserver"]
    assert len(ns_clusters) >= 1


def test_infra_fingerprint_model_defaults():
    fp = InfraFingerprint(domain="test.com")
    assert fp.domain == "test.com"
    assert fp.resolved_ips == []
    assert fp.tls_cert_sha256 is None
    assert fp.tls_cert_sans == []
