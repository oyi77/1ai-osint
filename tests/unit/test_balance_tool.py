"""Tests for CryptoBalanceTool and checker (pure logic only, no network calls)."""

import pytest
from unittest.mock import AsyncMock, patch

from src.modules.crypto.balance import CryptoBalanceTool
from src.modules.crypto.balance.chains import ETHEREUM, ChainConfig, ChainType
from src.modules.crypto.balance.checker import BalanceResult, apply_usd_prices
from src.models import ScanResult
from datetime import datetime, timezone

TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _mock_bal(addr="0xtest", chain="Ethereum", symbol="ETH"):
    return BalanceResult(address=addr, chain=chain, symbol=symbol, balance=0, balance_raw=0, usd_price=0, usd_value=0, derivation_path="")


class TestCryptoBalanceTool:
    def test_init_defaults(self):
        tool = CryptoBalanceTool()
        assert tool.name == "crypto_balance"
        assert tool.account_count == 1

    def test_init_custom_chains(self):
        tool = CryptoBalanceTool(chains=[ETHEREUM], account_count=3)
        assert tool.chains == [ETHEREUM]
        assert tool.account_count == 3

    @pytest.mark.asyncio
    async def test_search_delegates_to_scan(self):
        tool = CryptoBalanceTool()
        with patch.object(tool, 'scan', new_callable=AsyncMock) as mock_scan:
            now = datetime.now(timezone.utc)
            mock_scan.return_value = ScanResult(
                scan_id="t", module="crypto_balance", target="t",
                status="ok", findings=[], started_at=now, completed_at=now,
            )
            result = await tool.search("test")
            mock_scan.assert_called_once_with("test")
            assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_invalid_input(self):
        tool = CryptoBalanceTool()
        result = await tool.scan("not_anything_useful")
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_with_mocked_check(self):
        tool = CryptoBalanceTool(chains=[ETHEREUM])
        with patch("src.modules.crypto.balance.checker.check_balance", new_callable=AsyncMock) as mc:
            mc.return_value = _mock_bal()
            result = await tool.scan("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC10")
            assert isinstance(result, ScanResult)


class TestBalanceChecker:
    def test_apply_usd_prices_basic(self):
        results = [
            BalanceResult(address="0xa", chain="Ethereum", symbol="ETH", balance=1.5, balance_raw=1500000000000000000, usd_price=0, usd_value=0, derivation_path=""),
            BalanceResult(address="0xb", chain="Bitcoin", symbol="BTC", balance=0.1, balance_raw=10000000, usd_price=0, usd_value=0, derivation_path=""),
        ]
        prices = {"ethereum": 3000, "bitcoin": 60000}
        apply_usd_prices(results, prices)
        assert results[0].usd_price == 3000
        assert results[0].usd_value == 4500
        assert results[1].usd_price == 60000
        assert results[1].usd_value == 6000

    def test_apply_usd_prices_empty(self):
        apply_usd_prices([], {})

    @pytest.mark.asyncio
    async def test_check_evm_no_rpc(self):
        from src.modules.crypto.balance.checker import check_evm_balance
        chain = ChainConfig(name="N", symbol="N", chain_type=ChainType.EVM, rpc_url="", coin_id="n", derivation_paths=["m/44'/60'/0'/0/0"])
        r = await check_evm_balance("0xt", chain)
        assert "No RPC URL" in r.error

    @pytest.mark.asyncio
    async def test_get_usd_prices_mocked(self):
        from src.modules.crypto.balance.checker import get_usd_prices
        mock_resp = AsyncMock()
        mock_resp.json.return_value = {"bitcoin": {"usd": 60000}}
        mock_resp.raise_for_status = lambda: None
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.crypto.balance.checker.httpx.AsyncClient", return_value=mock_client):
            prices = await get_usd_prices(["bitcoin"])
            assert isinstance(prices, dict)