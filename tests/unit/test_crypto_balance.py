"""Tests for the crypto balance checker module."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.modules.crypto.balance.deriver import (
    detect_input_type,
    is_valid_mnemonic,
    derive_from_mnemonic,
    derive_from_privatekey,
    DerivedAddress,
)
from src.modules.crypto.balance.checker import (
    BalanceResult,
    apply_usd_prices,
    get_usd_prices,
)
from src.modules.crypto.balance.chains import (
    ETHEREUM,
    BITCOIN,
    SOLANA,
    BSC,
    POLYGON,
    ALL_CHAINS,
    CHAIN_MAP,
    ChainType,
)
from src.modules.crypto.balance import CryptoBalanceTool
from src.models import Severity


# --- Test Data ---

VALID_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
VALID_ETH_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
VALID_BTC_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
VALID_SOL_ADDRESS = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
VALID_PRIVATE_KEY = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"


# --- Chain Config Tests ---


class TestChainConfig:
    def test_all_chains_defined(self):
        assert len(ALL_CHAINS) == 5
        names = {c.name for c in ALL_CHAINS}
        assert "Ethereum" in names
        assert "Bitcoin" in names
        assert "Solana" in names

    def test_chain_map_lookup(self):
        assert CHAIN_MAP["ethereum"] is ETHEREUM
        assert CHAIN_MAP["eth"] is ETHEREUM
        assert CHAIN_MAP["bitcoin"] is BITCOIN
        assert CHAIN_MAP["btc"] is BITCOIN

    def test_chain_types(self):
        assert ETHEREUM.chain_type == ChainType.EVM
        assert BITCOIN.chain_type == ChainType.BITCOIN
        assert SOLANA.chain_type == ChainType.SOLANA

    def test_btc_has_multiple_paths(self):
        assert len(BITCOIN.derivation_paths) >= 3


# --- Deriver Tests ---


class TestDetectInputType:
    def test_valid_mnemonic(self):
        assert detect_input_type(VALID_MNEMONIC) == "mnemonic"

    def test_invalid_mnemonic_words(self):
        assert detect_input_type("hello world") == "unknown"

    def test_eth_address(self):
        assert detect_input_type(VALID_ETH_ADDRESS) == "evm_address"

    def test_btc_address(self):
        assert detect_input_type(VALID_BTC_ADDRESS) == "btc_address"

    def test_sol_address(self):
        assert detect_input_type(VALID_SOL_ADDRESS) == "sol_address"

    def test_private_key(self):
        assert detect_input_type(VALID_PRIVATE_KEY) == "private_key"

    def test_private_key_with_0x(self):
        assert detect_input_type("0x" + VALID_PRIVATE_KEY) == "private_key"

    def test_unknown(self):
        assert detect_input_type("not anything valid") == "unknown"

    def test_empty(self):
        assert detect_input_type("") == "unknown"


class TestMnemonicValidation:
    def test_valid_mnemonic(self):
        assert is_valid_mnemonic(VALID_MNEMONIC) is True

    def test_invalid_mnemonic(self):
        assert is_valid_mnemonic("this is not a valid mnemonic phrase at all") is False

    def test_empty(self):
        assert is_valid_mnemonic("") is False


class TestDeriveFromMnemonic:
    def test_derives_eth_address(self):
        results = derive_from_mnemonic(VALID_MNEMONIC, chains=[ETHEREUM])
        assert len(results) >= 1
        eth = results[0]
        assert eth.chain == "Ethereum"
        assert eth.address.startswith("0x")
        assert len(eth.address) == 42

    def test_derives_multiple_chains(self):
        results = derive_from_mnemonic(VALID_MNEMONIC, chains=[ETHEREUM, BITCOIN])
        chains_found = {r.chain for r in results}
        assert "Ethereum" in chains_found
        assert "Bitcoin" in chains_found

    def test_derives_btc_multiple_paths(self):
        results = derive_from_mnemonic(VALID_MNEMONIC, chains=[BITCOIN])
        assert len(results) >= 2  # At least BIP-44 legacy paths succeed
        paths = {r.derivation_path for r in results}
        assert "m/44'/0'/0'/0/0" in paths

    def test_count_parameter(self):
        results = derive_from_mnemonic(VALID_MNEMONIC, chains=[ETHEREUM], count=3)
        assert len(results) == 3 * len(ETHEREUM.derivation_paths)

    def test_invalid_mnemonic_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            derive_from_mnemonic("not a mnemonic", chains=[ETHEREUM])

    def test_all_chains(self):
        results = derive_from_mnemonic(VALID_MNEMONIC)
        chains_found = {r.chain for r in results}
        assert len(chains_found) >= 4  # ETH, BSC, Polygon, BTC, SOL

    def test_result_has_private_key(self):
        results = derive_from_mnemonic(VALID_MNEMONIC, chains=[ETHEREUM])
        assert results[0].private_key_hex is not None
        assert len(results[0].private_key_hex) == 64

    def test_deterministic(self):
        r1 = derive_from_mnemonic(VALID_MNEMONIC, chains=[ETHEREUM])
        r2 = derive_from_mnemonic(VALID_MNEMONIC, chains=[ETHEREUM])
        assert r1[0].address == r2[0].address


class TestDeriveFromPrivatekey:
    def test_derives_eth_address(self):
        result = derive_from_privatekey(VALID_PRIVATE_KEY, chain=ETHEREUM)
        assert result.address.startswith("0x")
        assert len(result.address) == 42
        assert result.chain == "Ethereum"

    def test_with_0x_prefix(self):
        result = derive_from_privatekey("0x" + VALID_PRIVATE_KEY, chain=ETHEREUM)
        assert result.address.startswith("0x")

    def test_invalid_key_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            derive_from_privatekey("notakey", chain=ETHEREUM)

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            derive_from_privatekey("abc123", chain=ETHEREUM)


# --- Checker Tests ---


class TestBalanceResult:
    def test_creation(self):
        r = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=1.5,
            balance_raw=1500000000000000000,
            usd_price=2000.0,
            usd_value=3000.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        assert r.balance == 1.5
        assert r.usd_value == 3000.0
        assert r.error is None


class TestApplyUsdPrices:
    def test_applies_prices(self):
        results = [
            BalanceResult(
                address="0x123",
                chain="Ethereum",
                symbol="ETH",
                balance=2.0,
                balance_raw=2000000000000000000,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="",
            ),
        ]
        prices = {"ethereum": 2500.0}
        apply_usd_prices(results, prices)
        assert results[0].usd_price == 2500.0
        assert results[0].usd_value == 5000.0

    def test_missing_price(self):
        results = [
            BalanceResult(
                address="0x123",
                chain="Unknown",
                symbol="UNK",
                balance=1.0,
                balance_raw=1000000000000000000,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="",
            ),
        ]
        apply_usd_prices(results, {})
        assert results[0].usd_price == 0.0
        assert results[0].usd_value == 0.0


@pytest.mark.asyncio
class TestGetUsdPrices:
    async def test_returns_prices(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"bitcoin": {"usd": 60000.0}}

        with patch(
            "httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp
        ):
            prices = await get_usd_prices(["bitcoin"])
            assert prices["bitcoin"] == 60000.0

    async def test_empty_input(self):
        prices = await get_usd_prices([])
        assert prices == {}

    async def test_api_error_returns_zeros(self):
        import src.modules.crypto.balance.checker as checker_mod

        checker_mod._price_cache.clear()
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("timeout")
        prices = await get_usd_prices(["bitcoin"], client=mock_client)
        assert prices["bitcoin"] == 0.0


# --- Module Tests ---


@pytest.mark.asyncio
class TestCryptoBalanceTool:
    async def test_scan_mnemonic(self):
        tool = CryptoBalanceTool(chains=[ETHEREUM])
        with patch(
            "src.modules.crypto.balance.check_balance", new_callable=AsyncMock
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0x123",
                chain="Ethereum",
                symbol="ETH",
                balance=1.5,
                balance_raw=1500000000000000000,
                usd_price=2000.0,
                usd_value=3000.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ):
                result = await tool.scan(VALID_MNEMONIC)
                assert result.status in ("ok", "partial")
                assert len(result.findings) >= 1

    async def test_scan_unknown_input(self):
        tool = CryptoBalanceTool()
        result = await tool.scan("not valid input at all")
        assert result.status == "error"

    async def test_scan_address(self):
        tool = CryptoBalanceTool(chains=[ETHEREUM])
        with patch(
            "src.modules.crypto.balance.check_balance", new_callable=AsyncMock
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address=VALID_ETH_ADDRESS,
                chain="Ethereum",
                symbol="ETH",
                balance=0.0,
                balance_raw=0,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="direct",
            )
            with patch(
                "src.modules.crypto.balance.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 0.0},
            ):
                result = await tool.scan(VALID_ETH_ADDRESS)
                assert result.status in ("ok", "partial")
                assert len(result.findings) >= 1

    async def test_analyze(self):
        from src.models import Finding, Severity

        findings = [
            Finding(
                id="1",
                module="crypto_balance",
                title="ETH balance",
                severity=Severity.HIGH,
                confidence=1.0,
                raw_data={
                    "chain": "Ethereum",
                    "symbol": "ETH",
                    "balance": 1.0,
                    "usd_value": 2000.0,
                    "address": "0x123",
                },
            ),
            Finding(
                id="2",
                module="crypto_balance",
                title="BTC balance",
                severity=Severity.INFO,
                confidence=1.0,
                raw_data={
                    "chain": "Bitcoin",
                    "symbol": "BTC",
                    "balance": 0.0,
                    "usd_value": 0.0,
                    "address": "1abc",
                },
            ),
        ]
        tool = CryptoBalanceTool()
        analysis = await tool.analyze(findings)
        assert analysis["total_usd_value"] == 2000.0
        assert analysis["has_funds"] is True
        assert "Ethereum" in analysis["by_chain"]

    async def test_learn_noop(self):
        tool = CryptoBalanceTool()
        await tool.learn({"feedback": "test"})
        # No-op, just verify it doesn't raise

    def test_name_and_description(self):
        tool = CryptoBalanceTool()
        assert tool.name == "crypto_balance"
        assert "balance" in tool.description.lower()


# --- API Rotation Tests ---

from src.modules.crypto.balance.api_rotation import EndpointRotator, EndpointHealth


class TestEndpointHealth:
    def test_initial_state(self):
        h = EndpointHealth(url="https://rpc1.example.com")
        assert h.is_disabled is False
        assert h.success_count == 0
        assert h.failure_count == 0
        assert h.consecutive_failures == 0

    def test_disable_after_threshold(self):
        import time

        h = EndpointHealth(url="https://rpc1.example.com")
        # Simulate 3 consecutive failures
        for _ in range(3):
            h.consecutive_failures += 1
            h.failure_count += 1
        h.disabled_at = time.monotonic()  # set to current time (within cooldown)
        assert h.is_disabled is True  # within cooldown

    def test_reenable_after_cooldown(self):
        import time

        h = EndpointHealth(url="https://rpc1.example.com")
        h.disabled_at = time.monotonic() - 310  # 310 seconds ago (cooldown is 300s)
        assert h.is_disabled is False  # cooldown expired, re-enabled
        assert h.consecutive_failures == 0  # reset


class TestEndpointRotator:
    def test_round_robin(self):
        rotator = EndpointRotator(
            ["https://rpc1.com", "https://rpc2.com", "https://rpc3.com"]
        )
        urls = [rotator.next() for _ in range(6)]
        # Should cycle through endpoints
        assert urls[0] != urls[1] or urls[1] != urls[2]
        assert set(urls[:3]) == {
            "https://rpc1.com",
            "https://rpc2.com",
            "https://rpc3.com",
        }

    @pytest.mark.asyncio
    async def test_report_success_resets_failures(self):
        rotator = EndpointRotator(["https://rpc1.com"])
        url = rotator.next()
        await rotator.report_failure(url)
        await rotator.report_failure(url)
        health = rotator.get_health(url)
        assert health is not None
        assert health.consecutive_failures == 2
        rotator.report_success(url)
        health = rotator.get_health(url)
        assert health is not None
        assert health.consecutive_failures == 0
        assert health.success_count == 1

    @pytest.mark.asyncio
    async def test_auto_disable_after_consecutive_failures(self):
        rotator = EndpointRotator(["https://rpc1.com", "https://rpc2.com"])
        url = rotator.next()
        for _ in range(10):
            await rotator.report_failure(url)
        health = rotator.get_health(url)
        assert health is not None
        assert health.is_disabled is True

    @pytest.mark.asyncio
    async def test_skips_disabled_endpoint(self):
        rotator = EndpointRotator(["https://rpc1.com", "https://rpc2.com"])
        url1 = rotator.next()
        for _ in range(10):
            await rotator.report_failure(url1)
        url2 = rotator.next()
        assert url2 != url1

    @pytest.mark.asyncio
    async def test_degraded_mode_when_all_disabled(self):
        rotator = EndpointRotator(["https://rpc1.com", "https://rpc2.com"])
        for url in rotator.endpoints:
            for _ in range(10):
                await rotator.report_failure(url)
        url = rotator.next()
        assert url in rotator.endpoints

    @pytest.mark.asyncio
    async def test_healthy_count(self):
        rotator = EndpointRotator(["https://rpc1.com", "https://rpc2.com"])
        assert rotator.healthy_count == 2
        url = rotator.next()
        for _ in range(10):
            await rotator.report_failure(url)
        assert rotator.healthy_count == 1

    def test_empty_endpoints_raises(self):
        with pytest.raises(ValueError, match="At least one"):
            EndpointRotator([])

    @pytest.mark.asyncio
    async def test_unknown_report_is_noop(self):
        rotator = EndpointRotator(["https://rpc1.com"])
        rotator.report_success("https://nonexistent.com")
        await rotator.report_failure("https://nonexistent.com")


# --- Targeted Search Tests ---

from src.modules.crypto.balance.targeted_search import (
    KnownMnemonicLookup,
    AccountRangeScan,
    FilteredRandomScan,
    TargetedScanResult,
    targeted_scan_to_scanresult,
)


class TestKnownMnemonicLookup:
    @pytest.mark.asyncio
    async def test_derives_and_checks(self):
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0x123",
                chain="Ethereum",
                symbol="ETH",
                balance=1.5,
                balance_raw=1500000000000000000,
                usd_price=2000.0,
                usd_value=3000.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ):
                lookup = KnownMnemonicLookup(mnemonic=VALID_MNEMONIC, chains=[ETHEREUM])
                result = await lookup.execute(scan_id="test-1")
                assert result.mode == "known_mnemonic"
                assert len(result.findings) >= 1
                assert result.addresses_checked >= 1
                assert result.has_hits is True

    @pytest.mark.asyncio
    async def test_invalid_mnemonic(self):
        with pytest.raises(ValueError, match="Invalid BIP-39 mnemonic"):
            KnownMnemonicLookup(mnemonic="not a valid mnemonic phrase")

    @pytest.mark.asyncio
    async def test_account_range(self):
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0x123",
                chain="Ethereum",
                symbol="ETH",
                balance=0.0,
                balance_raw=0,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ):
                lookup = KnownMnemonicLookup(
                    mnemonic=VALID_MNEMONIC,
                    chains=[ETHEREUM],
                    account_range=(0, 3),
                )
                result = await lookup.execute(scan_id="test-3")
                assert result.addresses_checked >= 3


class TestAccountRangeScan:
    @pytest.mark.asyncio
    async def test_scans_account_range(self):
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0x456",
                chain="Ethereum",
                symbol="ETH",
                balance=0.5,
                balance_raw=500000000000000000,
                usd_price=2000.0,
                usd_value=1000.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ):
                scanner = AccountRangeScan(
                    mnemonic=VALID_MNEMONIC, chain=ETHEREUM, start=0, end=5
                )
                result = await scanner.execute(scan_id="test-ar-1")
                assert result.mode == "account_range"
                assert result.addresses_checked == 5 * len(ETHEREUM.derivation_paths)
                assert len(result.findings) == 5 * len(ETHEREUM.derivation_paths)

    @pytest.mark.asyncio
    async def test_invalid_mnemonic(self):
        with pytest.raises(ValueError, match="Invalid BIP-39 mnemonic"):
            AccountRangeScan(mnemonic="not valid", chain=ETHEREUM)


class TestFilteredRandomScan:
    @pytest.mark.asyncio
    async def test_generates_and_checks(self):
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0x789",
                chain="Ethereum",
                symbol="ETH",
                balance=0.0,
                balance_raw=0,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ):
                scanner = FilteredRandomScan(chains=[ETHEREUM])
                result = await scanner.execute(scan_id="test-fr-1", iterations=3)
                assert result.mode == "filtered_random"
                assert result.addresses_checked >= 3

    @pytest.mark.asyncio
    async def test_filters_by_min_balance(self):
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            # All balances are 0, below min_balance
            mock_check.return_value = BalanceResult(
                address="0xabc",
                chain="Ethereum",
                symbol="ETH",
                balance=0.0,
                balance_raw=0,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ):
                scanner = FilteredRandomScan(chains=[ETHEREUM], min_balance=1.0)
                result = await scanner.execute(scan_id="test-fr-2", iterations=3)
                # No findings because all balances are below min_balance
                assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_reports_hits_above_threshold(self):
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0xdef",
                chain="Ethereum",
                symbol="ETH",
                balance=5.0,
                balance_raw=5000000000000000000,
                usd_price=2000.0,
                usd_value=10000.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ):
                scanner = FilteredRandomScan(chains=[ETHEREUM], min_balance=1.0)
                result = await scanner.execute(scan_id="test-fr-3", iterations=2)
                assert len(result.findings) == 2 * len(
                    ETHEREUM.derivation_paths
                )  # 2 iterations * chain paths each with balance
                assert result.has_hits is True


class TestTargetedScanResult:
    def test_to_scanresult(self):
        targeted = TargetedScanResult(
            scan_id="test-convert",
            mode="known_mnemonic",
            addresses_checked=5,
            chains_checked=["Ethereum"],
        )
        sr = targeted_scan_to_scanresult(targeted, target_label="test mnemonic")
        assert sr.scan_id == "test-convert"
        assert sr.module == "crypto_balance"
        assert sr.target == "test mnemonic"
        assert sr.status == "ok"


# --- Scanner Engine Tests ---

from src.modules.crypto.balance.scanner_engine import RandomScanner, ScannerStats


class TestScannerEngine:
    """Tests for RandomScanner worker pool, semaphore, and progress."""

    @pytest.mark.asyncio
    async def test_random_mode_delegates_to_scanner(self):
        tool = CryptoBalanceTool(chains=[ETHEREUM])
        mock_stats = ScannerStats(
            mnemonics_generated=5,
            addresses_checked=25,
            hits_found=0,
            api_errors=0,
        )
        mock_stats.start_time = mock_stats.start_time - 1.0
        with patch(
            "src.modules.crypto.balance.scanner_engine.RandomScanner"
        ) as MockScanner:
            instance = MockScanner.return_value
            instance.run = AsyncMock(return_value=mock_stats)
            result = await tool.scan("random", scan_mode="random", duration=5)
            assert result.status == "ok"
            assert result.metadata.get("mode") == "random"
            instance.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_targeted_mode_delegates_to_lookup(self):
        tool = CryptoBalanceTool(chains=[ETHEREUM])
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0x123",
                chain="Ethereum",
                symbol="ETH",
                balance=0.0,
                balance_raw=0,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ):
                result = await tool.scan(
                    VALID_MNEMONIC, scan_mode="targeted", account_count=2
                )
                assert result.status in ("ok", "partial")
                assert result.metadata.get("mode") == "known_mnemonic"

    @pytest.mark.asyncio
    async def test_scanner_stats_properties(self):
        stats = ScannerStats(
            mnemonics_generated=100, addresses_checked=500, hits_found=3, api_errors=2
        )
        assert stats.mnemonics_per_sec >= 0
        assert stats.elapsed >= 0

    @pytest.mark.asyncio
    async def test_scanner_worker_pool_runs(self):
        scanner = RandomScanner(workers=2, chains=[ETHEREUM])
        with patch(
            "src.modules.crypto.balance.deriver.derive_from_mnemonic_provider"
        ) as mock_derive:
            mock_derive.return_value = [
                DerivedAddress(
                    address="0x123",
                    chain="Ethereum",
                    symbol="ETH",
                    derivation_path="m/44'/60'/0'/0/0",
                    private_key_hex="a" * 64,
                ),
            ]
            from src.modules.crypto.balance.multicall import BatchBalanceResult
            with patch(
                "src.modules.crypto.balance.multicall.batch_check_balances",
                new_callable=AsyncMock,
            ) as mock_batch:
                mock_batch.return_value = [
                    BatchBalanceResult(address="0x123", balance_wei=0, error=None),
                ]
                stats = await scanner.run(duration_sec=2, max_mnemonics=5)
                assert stats.mnemonics_generated >= 1
                assert stats.addresses_checked >= 1

    @pytest.mark.asyncio
    async def test_scanner_semaphore_limits_concurrency(self):
        scanner = RandomScanner(workers=5, api_concurrency=2, chains=[ETHEREUM])
        with patch(
            "src.modules.crypto.balance.deriver.derive_from_mnemonic_provider"
        ) as mock_derive:
            mock_derive.return_value = [
                DerivedAddress(
                    address="0x123",
                    chain="Ethereum",
                    symbol="ETH",
                    derivation_path="m/44'/60'/0'/0/0",
                    private_key_hex="a" * 64,
                ),
            ]
            from src.modules.crypto.balance.multicall import BatchBalanceResult
            with patch(
                "src.modules.crypto.balance.multicall.batch_check_balances",
                new_callable=AsyncMock,
            ) as mock_batch:
                mock_batch.return_value = [
                    BatchBalanceResult(address="0x123", balance_wei=0, error=None),
                ]
                stats = await scanner.run(duration_sec=0.5, max_mnemonics=5)
                assert stats.mnemonics_generated >= 1


# --- Hit Logger Tests ---

from src.modules.crypto.balance.hit_logger import HitLogger


class TestHitLogger:
    """Tests for HitLogger aiosqlite persistence, alerts, and key stripping."""

    @pytest.mark.asyncio
    async def test_log_hit_strips_private_key(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            hl = HitLogger(db_path=db_path)
            await hl.start()
            await hl.log_hit(
                address="0xabc",
                chain="Ethereum",
                balance=1.5,
                usd_value=3000.0,
                private_key_hex="DEADBEEF" * 8,
                mnemonic_hash="hash123",
                derivation_path="m/44'/60'/0'/0/0",
                source="test",
            )
            await hl.flush()
            rows = await hl.query_recent(limit=10)
            assert len(rows) == 1
            assert "private_key_hex" not in rows[0]
            assert rows[0]["address"] == "0xabc"
            await hl.close()
        finally:
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_batch_flush(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            hl = HitLogger(db_path=db_path)
            await hl.start()
            for i in range(5):
                await hl.log_hit(
                    address=f"0x{i:040x}",
                    chain="Ethereum",
                    balance=float(i),
                    usd_value=float(i) * 2000.0,
                )
            rows = await hl.query_recent()
            assert len(rows) == 0
            await hl.flush()
            rows = await hl.query_recent()
            assert len(rows) == 5
            await hl.close()
        finally:
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_auto_flush_at_batch_size(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            hl = HitLogger(db_path=db_path)
            await hl.start()
            for i in range(10):
                await hl.log_hit(
                    address=f"0x{i:040x}",
                    chain="Ethereum",
                    balance=float(i),
                    usd_value=float(i) * 2000.0,
                )
            rows = await hl.query_recent()
            assert len(rows) == 10
            await hl.close()
        finally:
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_telegram_alert_mock(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            hl = HitLogger(
                db_path=db_path, telegram_token="fake-token", telegram_chat_id="12345"
            )
            await hl.start()
            with patch.object(hl, "_send_telegram", new_callable=AsyncMock) as mock_tg:
                await hl.log_hit(
                    address="0xabc", chain="Ethereum", balance=1.0, usd_value=2000.0
                )
                await hl.flush()
                mock_tg.assert_called_once()
            await hl.close()
        finally:
            os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_no_alert_for_zero_balance(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            hl = HitLogger(
                db_path=db_path, telegram_token="fake-token", telegram_chat_id="12345"
            )
            await hl.start()
            with patch.object(hl, "_send_telegram", new_callable=AsyncMock) as mock_tg:
                await hl.log_hit(
                    address="0xabc", chain="Ethereum", balance=0.0, usd_value=0.0
                )
                await hl.flush()
                mock_tg.assert_not_called()
            await hl.close()
        finally:
            os.unlink(db_path)

    def test_hash_mnemonic(self):
        h1 = HitLogger.hash_mnemonic("abandon about")
        h2 = HitLogger.hash_mnemonic("abandon about")
        h3 = HitLogger.hash_mnemonic("different phrase")
        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 64


# --- End-to-End Tests (all mocked APIs) ---


class TestEndToEnd:
    """End-to-end tests for targeted scan -> hit -> log -> alert pipeline."""

    @pytest.mark.asyncio
    async def test_targeted_hit_with_logging(self):
        """Test: targeted scan finds a hit, creates finding with correct severity."""
        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = BalanceResult(
                address="0xrich",
                chain="Ethereum",
                symbol="ETH",
                balance=10.0,
                balance_raw=10000000000000000000,
                usd_price=2000.0,
                usd_value=20000.0,
                derivation_path="m/44'/60'/0'/0/0",
            )
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ):
                lookup = KnownMnemonicLookup(mnemonic=VALID_MNEMONIC, chains=[ETHEREUM])
                result = await lookup.execute(scan_id="e2e-1")

                assert result.has_hits is True
                # Should have CRITICAL finding (>$1000)
                critical_findings = [
                    f for f in result.findings if f.severity == Severity.CRITICAL
                ]
                assert len(critical_findings) >= 1

                # Convert to ScanResult
                sr = targeted_scan_to_scanresult(result)
                assert sr.critical_count >= 1
                assert sr.status == "ok"

    @pytest.mark.asyncio
    async def test_account_range_scan_e2e(self):
        """Test: account range scan across multiple accounts."""
        call_count = 0

        async def mock_balance(address, chain, derivation_path=""):
            nonlocal call_count
            call_count += 1
            balance = 1.0 if call_count == 3 else 0.0  # Only 3rd account has balance
            return BalanceResult(
                address=address,
                chain=chain.name,
                symbol=chain.symbol,
                balance=balance,
                balance_raw=int(balance * 1e18),
                usd_price=2000.0,
                usd_value=balance * 2000.0,
                derivation_path=derivation_path,
            )

        with patch(
            "src.modules.crypto.balance.targeted_search.check_balance",
            side_effect=mock_balance,
        ):
            with patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ):
                scanner = AccountRangeScan(
                    mnemonic=VALID_MNEMONIC, chain=ETHEREUM, start=0, end=5
                )
                result = await scanner.execute(scan_id="e2e-ar-1")

                assert result.addresses_checked == 5 * len(ETHEREUM.derivation_paths)
                # Only account 2 should have a hit
                hit_findings = [
                    f
                    for f in result.findings
                    if f.severity in (Severity.HIGH, Severity.CRITICAL)
                ]
                assert len(hit_findings) == 1

    @pytest.mark.asyncio
    async def test_hit_logger_e2e_with_alert(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            hl = HitLogger(
                db_path=db_path, telegram_token="fake-token", telegram_chat_id="12345"
            )
            await hl.start()
            with patch.object(hl, "_send_telegram", new_callable=AsyncMock) as mock_tg:
                await hl.log_hit(
                    address="0xrich",
                    chain="Ethereum",
                    balance=10.0,
                    usd_value=20000.0,
                    mnemonic_hash="abc123",
                    derivation_path="m/44'/60'/0'/0/0",
                    source="random_scan",
                )
                await hl.flush()
                mock_tg.assert_called_once()
                rows = await hl.query_recent()
                assert len(rows) == 1
                assert rows[0]["address"] == "0xrich"
                assert rows[0]["balance"] == 10.0
                assert "private_key_hex" not in rows[0]
            await hl.close()
        finally:
            os.unlink(db_path)
