"""Unit tests for DomainReconTool SSRF guard and rate limiting.

Pins the contract introduced with the SSRF-hardening pass: private / loopback
targets are refused before any HTTP client is created, every external call is
gated behind the module rate limiter, and per-task failures degrade gracefully
without marking the whole scan failed.

Run with: python -m pytest tests/unit/test_domain_recon.py -v --tb=short
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from src.modules.domain_recon import DomainReconTool


def _make_tool() -> DomainReconTool:
    tool = DomainReconTool(timeout=5.0)
    tool._rate_limiter = MagicMock()
    tool._rate_limiter.acquire_async = AsyncMock(return_value=0.0)
    return tool


def _make_client() -> AsyncMock:
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    return mock_client


def _make_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<whois/>"
    resp.headers = {"server": "nginx", "x-powered-by": "PHP"}
    resp.json.side_effect = [
        {"Answer": [{"data": "mail.example.com", "type": 15}]},  # DNS
        [{"name_value": "a.example.com\nb.example.com"}],  # subdomains
        [{"name": "example.com", "not_before": "2026-01-01"}],  # CT logs
    ]
    return resp


async def test_scan_blocks_private_target():
    tool = _make_tool()
    with patch("src.modules.domain_recon.httpx.AsyncClient") as m:
        result = await tool.scan("127.0.0.1")
    assert result.status == "blocked"
    assert "SSRF" in result.metadata["reason"]
    m.assert_not_called()


async def test_scan_public_domain_ok():
    tool = _make_tool()
    resp = _make_response()
    client = _make_client()
    client.get = AsyncMock(return_value=resp)
    with patch("src.modules.domain_recon.httpx.AsyncClient", return_value=client):
        result = await tool.scan("example.com")
    assert result.status == "ok"
    assert len(result.findings) == 5
    assert tool._rate_limiter.acquire_async.await_count == 5
    assert result.metadata["tasks_completed"] == 5
    assert result.metadata["tasks_failed"] == 0


async def test_scan_handles_task_errors_gracefully():
    tool = _make_tool()
    client = _make_client()
    client.get = AsyncMock(side_effect=Exception("timeout"))
    with patch("src.modules.domain_recon.httpx.AsyncClient", return_value=client):
        result = await tool.scan("example.com")
    assert result.status == "ok"
    assert result.findings == []
    assert result.metadata["tasks_failed"] == 0
