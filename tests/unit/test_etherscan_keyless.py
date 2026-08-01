"""Unit tests for Etherscan keyless mode (0-API mode)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.sources.etherscan_source import EtherscanSource


def _mock_client_get(payload: dict, status_code: int = 200):
    resp = MagicMock(status_code=status_code)
    resp.json.return_value = payload
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.get.return_value = resp
    return client


@pytest.mark.asyncio
async def test_keyless_makes_requests_without_apikey_param() -> None:
    client = _mock_client_get({"status": "1", "result": []})
    with patch("src.modules.sources.etherscan_source.httpx.AsyncClient", return_value=client):
        source = EtherscanSource(api_key="", request_delay=0)
        leaks = await source.search_for_address("0xdeadbeef")

    assert leaks == []
    assert client.get.call_count == 2
    for call in client.get.call_args_list:
        assert "apikey" not in call.kwargs["params"]
        assert call.args[0] == "https://api.etherscan.io/api"


@pytest.mark.asyncio
async def test_keyed_attaches_apikey_to_both_requests() -> None:
    client = _mock_client_get({"status": "1", "result": []})
    with patch("src.modules.sources.etherscan_source.httpx.AsyncClient", return_value=client):
        source = EtherscanSource(api_key="k123", request_delay=0)
        await source.search_for_address("0xdeadbeef")

    assert client.get.call_count == 2
    for call in client.get.call_args_list:
        assert call.kwargs["params"]["apikey"] == "k123"


@pytest.mark.asyncio
async def test_parses_transactions_and_tokens() -> None:
    client = _mock_client_get(
        {
            "status": "1",
            "result": [
                {"hash": "0xabc", "from": "0xa", "to": "0xb", "value": "100"},
                {"tokenName": "USDC", "tokenSymbol": "USDC", "from": "0xa", "to": "0xb", "value": "5"},
            ],
        }
    )
    with patch("src.modules.sources.etherscan_source.httpx.AsyncClient", return_value=client):
        source = EtherscanSource(api_key="", request_delay=0)
        leaks = await source.search_for_address("0xdeadbeef")

    names = [leak.source_name for leak in leaks]
    assert "etherscan" in names
    assert "etherscan_token" in names
    assert any("0xabc" in leak.text for leak in leaks)
    assert any("USDC" in leak.text for leak in leaks)
