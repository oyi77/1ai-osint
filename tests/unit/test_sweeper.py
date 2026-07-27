"""Tests for sweeper.py uncovered branches."""

from unittest.mock import AsyncMock, patch

import pytest

from src.modules.crypto.balance.chains import ChainConfig, ChainType
from src.modules.crypto.balance.sweeper import (
    DESTINATION_WALLETS,
    Sweeper,
)


class TestSweeperCore:
    def test_get_destination_known_chain(self):
        sweeper = Sweeper()
        assert sweeper.get_destination("ethereum") == DESTINATION_WALLETS["ethereum"]
        assert sweeper.get_destination("solana") == DESTINATION_WALLETS["solana"]

    def test_get_destination_unknown_chain(self):
        sweeper = Sweeper()
        assert sweeper.get_destination("nonexistent") is None

    def test_get_destination_case_insensitive(self):
        sweeper = Sweeper()
        assert sweeper.get_destination("Ethereum") == DESTINATION_WALLETS["ethereum"]

    @pytest.mark.asyncio
    async def test_close_no_client(self):
        sweeper = Sweeper()
        await sweeper.close()  # should not raise

    @pytest.mark.asyncio
    async def test_close_with_client(self):
        mock_client = AsyncMock()
        sweeper = Sweeper(client=mock_client)
        await sweeper.close()  # should not raise (didn't create it)

    @pytest.mark.asyncio
    async def test_sweep_no_destination(self):
        sweeper = Sweeper()
        chain = ChainConfig(
            name="UnknownChain",
            symbol="UNK",
            chain_type=ChainType.EVM,
            rpc_url="http://localhost",
            coin_id="unknown",
            derivation_paths=["m/44'/60'/0'/0/0"],
        )
        result = await sweeper.sweep("0x" + "ab" * 32, chain, "0xsrc", 1000)
        assert not result.success
        assert "No destination wallet" in result.error

    @pytest.mark.asyncio
    async def test_sweep_zero_balance(self):
        sweeper = Sweeper()
        chain = ChainConfig(
            name="Ethereum",
            symbol="ETH",
            chain_type=ChainType.EVM,
            rpc_url="http://localhost",
            coin_id="ethereum",
            derivation_paths=["m/44'/60'/0'/0/0"],
        )
        result = await sweeper.sweep("0x" + "ab" * 32, chain, "0xsrc", 0)
        assert not result.success
        assert "Zero balance" in result.error

    @pytest.mark.asyncio
    async def test_sweep_negative_balance(self):
        sweeper = Sweeper()
        chain = ChainConfig(
            name="Ethereum",
            symbol="ETH",
            chain_type=ChainType.EVM,
            rpc_url="http://localhost",
            coin_id="ethereum",
            derivation_paths=["m/44'/60'/0'/0/0"],
        )
        result = await sweeper.sweep("0x" + "ab" * 32, chain, "0xsrc", -100)
        assert not result.success
        assert "Zero balance" in result.error

    @pytest.mark.asyncio
    async def test_sweep_unsupported_chain_type(self):
        sweeper = Sweeper()
        chain = ChainConfig(
            name="Unknown",
            symbol="UNK",
            chain_type=ChainType.BITCOIN,
            rpc_url="http://localhost",
            coin_id="unknown",
            derivation_paths=["m/44'/0'/0'/0/0"],
        )
        # BITCOIN chain_type but no real RPC - should hit the chain type path
        # and fail inside _sweep_btc (which requires blockstream API)
        result = await sweeper.sweep("0x" + "ab" * 32, chain, "src_addr", 100000)
        assert not result.success

    @pytest.mark.asyncio
    async def test_sweep_evm_insufficient_gas(self):
        """Sweep EVM with too little balance should fail on gas."""
        sweeper = Sweeper()
        chain = ChainConfig(
            name="Ethereum",
            symbol="ETH",
            chain_type=ChainType.EVM,
            rpc_url="http://localhost",
            coin_id="ethereum",
            derivation_paths=["m/44'/60'/0'/0/0"],
            decimals=18,
        )
        # Balance is too low — even gas estimation may fail
        result = await sweeper.sweep("0x" + "ab" * 32, chain, "0xsrc", 1000)
        assert not result.success

    @pytest.mark.asyncio
    async def test_sweep_exception_handling(self):
        """Sweep should catch exceptions and return error result."""
        sweeper = Sweeper()
        chain = ChainConfig(
            name="Ethereum",
            symbol="ETH",
            chain_type=ChainType.EVM,
            rpc_url="http://localhost",
            coin_id="ethereum",
            derivation_paths=["m/44'/60'/0'/0/0"],
        )

        with patch.object(sweeper, "_sweep_evm", side_effect=RuntimeError("test error")):
            result = await sweeper.sweep("0x" + "ab" * 32, chain, "0xsrc", 1000000000000000000)
            assert not result.success
            assert "test error" in result.error
