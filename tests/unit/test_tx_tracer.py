"""Unit tests for BlockchainTxTracer module.

The tracer never fabricates transaction data: without an API key (EVM/BTC) or
a Solana RPC URL, scans return an honest no-data INFO finding with
``traced: False`` instead of mock mixer/exchange transactions.
"""

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
async def test_tracer_evm_no_key_no_fabricated_intel():
    tracer = BlockchainTxTracer(zkit_salt="test")
    tracer.etherscan_key = ""
    target = "0xde515dfac77777aaaaabbbbccccdddd000000000"

    res = await tracer.scan(target)
    assert res.status == "ok"
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.severity == Severity.INFO
    assert finding.confidence == 0.3
    assert finding.raw_data["traced"] is False
    assert finding.raw_data["total_transactions_traced"] == 0
    assert finding.raw_data["mixer_interactions"] == 0
    assert finding.raw_data["exchange_interactions"] == 0
    assert finding.raw_data["risk_score"] == 0.1
    assert finding.raw_data["transactions"] == []


@pytest.mark.asyncio
async def test_tracer_btc_no_key_no_fabricated_intel():
    tracer = BlockchainTxTracer(zkit_salt="test")
    tracer.blockchair_key = ""

    btc_target = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    res = await tracer.scan(btc_target)
    assert res.status == "ok"
    finding = res.findings[0]
    assert finding.severity == Severity.INFO
    assert finding.confidence == 0.3
    assert finding.raw_data["traced"] is False
    assert finding.raw_data["chain"] == "Bitcoin"
    assert finding.raw_data["mixer_interactions"] == 0


@pytest.mark.asyncio
async def test_tracer_solana_no_rpc_no_fabricated_intel(monkeypatch):
    monkeypatch.delenv("SOLANA_RPC_URL", raising=False)
    tracer = BlockchainTxTracer(zkit_salt="test")
    sol_target = "HN7cAB21Stwfa5gC183vESgM9Cg9Jz9Jz9Jz9Jz9Jz9J"
    res = await tracer.scan(sol_target)
    assert res.status == "ok"
    finding = res.findings[0]
    assert finding.raw_data["chain"] == "Solana"
    assert finding.raw_data["traced"] is False
    assert finding.confidence == 0.3


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
async def test_tracer_evm_mixer_flagged_critical():
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

        res = await tracer.scan(target)
    assert res.status == "ok"
    finding = res.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 1.0
    assert finding.raw_data["traced"] is True
    assert finding.raw_data["mixer_interactions"] == 1
    assert finding.raw_data["risk_score"] > 0.7


@pytest.mark.asyncio
async def test_tracer_btc_blockchair_query():
    tracer = BlockchainTxTracer(zkit_salt="test")
    tracer.blockchair_key = "fake_key"
    btc_target = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

    mock_resp = {
        "data": {
            btc_target: {
                "transactions": [
                    {
                        "hash": "btc-tx-1",
                        "time": 1609459200,
                        "output_value": 5000,
                    }
                ]
            }
        }
    }

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json = lambda: mock_resp

        txs = await tracer._trace_btc(btc_target)
    assert len(txs) == 1
    assert txs[0]["hash"] == "btc-tx-1"
    assert txs[0]["value"] == 5000


@pytest.mark.asyncio
async def test_tracer_solana_rpc_query(monkeypatch):
    monkeypatch.setenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
    tracer = BlockchainTxTracer(zkit_salt="test")
    sol_target = "HN7cAB21Stwfa5gC183vESgM9Cg9Jz9Jz9Jz9Jz9Jz9J"

    sig_resp = {
        "jsonrpc": "2.0",
        "result": [
            {"signature": "sig1"},
            {"signature": "sig2"},
        ],
    }
    tx_resp = {
        "jsonrpc": "2.0",
        "result": {
            "blockTime": 1609459200,
            "transaction": {
                "message": {
                    "accountKeys": ["wallet_a", sol_target, "wallet_b"],
                }
            },
            "meta": {
                "preBalances": [100, 200, 0],
                "postBalances": [100, 150, 0],
            },
        },
    }

    calls = {"n": 0}

    async def fake_post(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResp(sig_resp)
        return _FakeResp(tx_resp)

    class _FakeResp:
        def __init__(self, payload):
            self._payload = payload

        @property
        def status_code(self):
            return 200

        def json(self):
            return self._payload

    with patch("httpx.AsyncClient.post", side_effect=fake_post):
        txs = await tracer._trace_solana(sol_target)
    assert len(txs) == 2
    assert txs[0]["hash"] == "sig1"
    assert txs[0]["from"] == "wallet_a"
    assert txs[0]["value"] == 50


@pytest.mark.asyncio
async def test_tracer_analyze_no_data():
    tracer = BlockchainTxTracer(zkit_salt="test")
    tracer.etherscan_key = ""
    target = "0xde515dfac77777aaaaabbbbccccdddd000000000"
    res = await tracer.scan(target)

    analysis = await tracer.analyze(res)
    assert analysis["address"] == target
    assert analysis["mixer_interactions"] == 0
    assert analysis["risk_score"] == 0.1
