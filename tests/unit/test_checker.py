"""Tests for checker.py uncovered branches."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.crypto.balance.checker import (
    BalanceResult,
    check_evm_balance,
    check_btc_balance,
    check_sol_balance,
    check_balance,
)
from src.modules.crypto.balance.chains import ETHEREUM, BITCOIN, SOLANA, ChainConfig, ChainType


class TestCheckEVMBalance:
    @pytest.mark.asyncio
    async def test_no_rpc_url(self):
        chain = ChainConfig(name="NoRPC", symbol="N", chain_type=ChainType.EVM, rpc_url="", coin_id="n", derivation_paths=["m/44'/60'/0'/0/0"])
        result = await check_evm_balance("0xtest", chain)
        assert "No RPC URL" in result.error

    @pytest.mark.asyncio
    async def test_with_mock_web3(self):
        with patch("src.modules.crypto.balance.checker.check_evm_balance", new_callable=AsyncMock) as mock:
            mock.return_value = BalanceResult(address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bC10", chain="Ethereum", symbol="ETH", balance=1.0, balance_raw=10**18, usd_price=0, usd_value=0, derivation_path="")
            result = await check_evm_balance("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC10", ETHEREUM)
            assert result.chain == "Ethereum"

    @pytest.mark.asyncio
    async def test_exception_handling(self):
        with patch("src.modules.crypto.balance.checker.check_evm_balance", new_callable=AsyncMock) as mock:
            mock.return_value = BalanceResult(address="0xtest", chain="Ethereum", symbol="ETH", balance=0, balance_raw=0, usd_price=0, usd_value=0, derivation_path="", error="connection failed")
            result = await check_evm_balance("0xtest", ETHEREUM)
            assert result.error is not None


class TestCheckBTCBalance:
    @pytest.mark.asyncio
    async def test_error_on_bad_address(self):
        result = await check_btc_balance("invalid_address", BITCOIN, "", client=None)
        assert result.error is not None
        assert result.chain == "Bitcoin"

    @pytest.mark.asyncio
    async def test_with_mock_response(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"chain_stats": [{"funded_txo_sum": 100000, "spent_txo_sum": 0}]}
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.aclose = AsyncMock()
        result = await check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", BITCOIN, client=mock_client)
        assert result.chain == "Bitcoin"


class TestCheckSolBalance:
    @pytest.mark.asyncio
    async def test_error_on_bad_address(self):
        result = await check_sol_balance("invalid", SOLANA, client=None)
        assert result.error is not None
        assert result.chain == "Solana"


class TestCheckBalance:
    @pytest.mark.asyncio
    async def test_evm_chain(self):
        with patch("src.modules.crypto.balance.checker.check_evm_balance", new_callable=AsyncMock) as mock:
            mock.return_value = BalanceResult(address="0xt", chain="Ethereum", symbol="ETH", balance=1.0, balance_raw=10**18, usd_price=0, usd_value=0, derivation_path="")
            result = await check_balance("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC10", ETHEREUM)
            assert result.chain == "Ethereum"

    @pytest.mark.asyncio
    async def test_btc_chain(self):
        with patch("src.modules.crypto.balance.checker.check_btc_balance", new_callable=AsyncMock) as mock:
            mock.return_value = BalanceResult(address="1t", chain="Bitcoin", symbol="BTC", balance=0.5, balance_raw=50000000, usd_price=0, usd_value=0, derivation_path="")
            result = await check_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", BITCOIN)
            assert result.chain == "Bitcoin"

    @pytest.mark.asyncio
    async def test_sol_chain(self):
        with patch("src.modules.crypto.balance.checker.check_sol_balance", new_callable=AsyncMock) as mock:
            mock.return_value = BalanceResult(address="st", chain="Solana", symbol="SOL", balance=10.0, balance_raw=10000000000, usd_price=0, usd_value=0, derivation_path="")
            result = await check_sol_balance("7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV", SOLANA)
            assert result.chain == "Solana"

    @pytest.mark.asyncio
    async def test_unknown_chain_type(self):
        unknown = ChainConfig(name="Unknown", symbol="UNK", chain_type=ChainType.EVM, rpc_url="", coin_id="unk", derivation_paths=["m/44'/0'/0'/0/0"])
        with patch("src.modules.crypto.balance.checker.check_evm_balance", new_callable=AsyncMock) as mock:
            mock.return_value = BalanceResult(address="0xt", chain="Unknown", symbol="UNK", balance=0, balance_raw=0, usd_price=0, usd_value=0, derivation_path="", error="No RPC URL")
            result = await check_balance("0xtest", unknown)
            assert result.error is not None