"""Unit tests for the Shodan keyless InternetDB fallback (0-API mode)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.sources.base import RawLeak
from src.modules.sources.shodan_source import ShodanSource


def _mock_client_get(payload: dict, status_code: int = 200):
    resp = MagicMock(status_code=status_code)
    resp.json.return_value = payload
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.get.return_value = resp
    return client


@pytest.mark.asyncio
async def test_keyless_falls_back_to_internetdb() -> None:
    client = _mock_client_get(
        {
            "ports": [22, 443],
            "hostnames": ["h1.example"],
            "cpes": ["cpe:/a:openssh"],
            "vulns": ["CVE-2021-1234"],
            "tags": ["database"],
        }
    )
    with patch("src.modules.sources.shodan_source.httpx.AsyncClient", return_value=client):
        source = ShodanSource(api_key="", request_delay=0)
        leaks = await source.search_for_address("8.8.8.8")

    assert len(leaks) == 6
    assert all(isinstance(leak, RawLeak) for leak in leaks)
    assert all(leak.source_name == "shodan_internetdb" for leak in leaks)
    assert any("CVE-2021-1234" in leak.text for leak in leaks)
    assert any("Open port: 22" in leak.text for leak in leaks)
    url = client.get.call_args.args[0]
    assert url.startswith("https://internetdb.shodan.io/8.8.8.8")


@pytest.mark.asyncio
async def test_keyless_domain_returns_empty_without_network_call() -> None:
    client = AsyncMock()
    with patch("src.modules.sources.shodan_source.httpx.AsyncClient", return_value=client):
        source = ShodanSource(api_key="", request_delay=0)
        leaks = await source.search_for_address("example.com")

    assert leaks == []
    client.get.assert_not_called()


@pytest.mark.asyncio
async def test_keyless_http_error_returns_empty() -> None:
    client = _mock_client_get({}, status_code=403)
    with patch("src.modules.sources.shodan_source.httpx.AsyncClient", return_value=client):
        source = ShodanSource(api_key="", request_delay=0)
        leaks = await source.search_for_address("1.1.1.1")

    assert leaks == []


@pytest.mark.asyncio
async def test_keyed_uses_shodan_api() -> None:
    client = _mock_client_get({"data": [{"data": "SSH banner here"}]})
    with patch("src.modules.sources.shodan_source.httpx.AsyncClient", return_value=client):
        source = ShodanSource(api_key="sekrit", request_delay=0)
        leaks = await source.search_for_address("8.8.8.8")

    assert len(leaks) == 1
    assert leaks[0].source_name == "shodan"
    assert "SSH banner here" in leaks[0].text
    url = client.get.call_args.args[0]
    assert url.startswith("https://api.shodan.io/shodan/host/8.8.8.8")
