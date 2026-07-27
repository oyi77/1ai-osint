"""Unit tests for BlockchainTxTracer module."""

from unittest.mock import patch

import pytest

from src.core.models import Severity
from src.modules.crypto.tx_tracer import BlockchainTxTracer


@pytest.mark.asyncio
async def test_tracer_invalid_target():
    tracer = BlockchainTxTracer(zkit_salt="test")
    res = await tracer.scan("not_an_address")
    assert res.status == "error"
    assert "not a valid blockchain address" in res.error


@pytest.mark.asyncio
async def test_tracer_evm_mixers():
    tracer = BlockchainTxTracer(zkit_salt="test")
    # Using mock address that is formatted correctly
    target = "0xde515dfac77777aaaaabbbbccccdddd000000000"

    res = await tracer.scan(target)
    assert res.status == "ok"
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.raw_data["mixer_interactions"] > 0
    assert finding.raw_data["risk_score"] > 0.7


@pytest.mark.asyncio
async def test_tracer_btc_exchange():
    tracer = BlockchainTxTracer(zkit_salt="test")

    # We test with a standard BTC address formats
    btc_target = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    res = await tracer.scan(btc_target)
    assert res.status == "ok"
    finding = res.findings[0]
    assert finding.raw_data["mixer_interactions"] > 0  # Mixer Sinbad is matched in tracer trace mock
    assert finding.raw_data["risk_score"] >= 0.7


@pytest.mark.asyncio
async def test_tracer_solana():
    tracer = BlockchainTxTracer(zkit_salt="test")
    sol_target = "HN7cAB21Stwfa5gC183vESgM9Cg9Jz9Jz9Jz9Jz9Jz9J"
    res = await tracer.scan(sol_target)
    assert res.status == "ok"
    finding = res.findings[0]
    assert finding.raw_data["chain"] == "Solana"


@pytest.mark.asyncio
async def test_tracer_etherscan_api_query():
    tracer = BlockchainTxTracer(zkit_salt="test")
    tracer.etherscan_key = "fake_key"
    target = "0xde515dfac77777aaaaabbbbccccdddd000000000"

    mock_resp = {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "hash": "0xhash1",
                "from": "0x777777c9898d384f785ee44acfe945efdff5f3e0",
                "to": target,
                "value": "1000000000000000000",
                "timeStamp": "1609459200",
            }
        ],
    }

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = lambda: mock_resp

        txs = await tracer._trace_evm(target)
        assert len(txs) == 1
        assert txs[0]["hash"] == "0xhash1"
        assert txs[0]["from"] == "0x777777c9898d384f785ee44acfe945efdff5f3e0"


@pytest.mark.asyncio
async def test_tracer_analyze():
    tracer = BlockchainTxTracer(zkit_salt="test")
    target = "0xde515dfac77777aaaaabbbbccccdddd000000000"
    res = await tracer.scan(target)

    analysis = await tracer.analyze(res)
    assert analysis["address"] == target
    assert analysis["mixer_interactions"] > 0
    assert analysis["risk_score"] > 0.7
