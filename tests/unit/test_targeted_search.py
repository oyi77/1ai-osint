"""Tests for the targeted search module: known mnemonic, account range, and filtered random scan."""

from unittest.mock import AsyncMock, patch

import pytest

from src.modules.crypto.balance.chains import ALL_CHAINS, ETHEREUM
from src.modules.crypto.balance.checker import BalanceResult
from src.modules.crypto.balance.targeted_search import (
    AccountRangeScan,
    FilteredRandomScan,
    KnownMnemonicLookup,
    TargetedScanResult,
    targeted_scan_to_scanresult,
)

VALID_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


# --- TargetedScanResult Tests ---


class TestTargetedScanResult:
    def test_creation(self):
        result = TargetedScanResult(scan_id="test-001", mode="known_mnemonic")
        assert result.scan_id == "test-001"
        assert result.mode == "known_mnemonic"
        assert result.findings == []
        assert result.addresses_checked == 0
        assert result.errors == []
        assert result.has_hits is False


# --- targeted_scan_to_scanresult Tests ---


class TestTargetedScanToScanResult:
    def test_converts_ok_status(self):
        targeted = TargetedScanResult(
            scan_id="test-001",
            mode="known_mnemonic",
            addresses_checked=5,
            chains_checked=["Ethereum"],
        )
        result = targeted_scan_to_scanresult(targeted, target_label="test_target")
        assert result.status == "ok"
        assert result.scan_id == "test-001"
        assert result.module == "crypto_balance"
        assert result.target == "test_target"
        assert result.metadata["mode"] == "known_mnemonic"
        assert result.metadata["addresses_checked"] == 5

    def test_converts_error_status(self):
        targeted = TargetedScanResult(
            scan_id="test-002",
            mode="known_mnemonic",
            errors=["Invalid mnemonic"],
        )
        result = targeted_scan_to_scanresult(targeted)
        assert result.status == "error"

    def test_converts_partial_status(self):
        from src.core.models import Finding, Severity

        targeted = TargetedScanResult(
            scan_id="test-003",
            mode="known_mnemonic",
            findings=[
                Finding(
                    id="f1",
                    module="crypto_balance",
                    title="test",
                    severity=Severity.INFO,
                    confidence=1.0,
                )
            ],
            errors=["Some error"],
        )
        result = targeted_scan_to_scanresult(targeted)
        assert result.status == "partial"


# --- KnownMnemonicLookup Tests ---


class TestKnownMnemonicLookup:
    def test_invalid_mnemonic_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            KnownMnemonicLookup(mnemonic="not a valid mnemonic")

    async def test_execute_with_mocked_balances(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=1.5,
            balance_raw=1500000000000000000,
            usd_price=2000.0,
            usd_value=3000.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ),
        ):
            lookup = KnownMnemonicLookup(
                mnemonic=VALID_MNEMONIC,
                chains=[ETHEREUM],
                account_range=(0, 1),
            )
            result = await lookup.execute(scan_id="test-km-001")
            assert isinstance(result, TargetedScanResult)
            assert result.mode == "known_mnemonic"
            assert len(result.findings) >= 1
            assert result.addresses_checked >= 1

    async def test_execute_all_chains(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=0.0,
            balance_raw=0,
            usd_price=0.0,
            usd_value=0.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            lookup = KnownMnemonicLookup(mnemonic=VALID_MNEMONIC)
            result = await lookup.execute(scan_id="test-km-002")
            assert result.addresses_checked > 5  # All chains derive multiple addresses

    async def test_high_balance_sets_critical_severity(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=10.0,
            balance_raw=10000000000000000000,
            usd_price=2000.0,
            usd_value=20000.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ),
        ):
            lookup = KnownMnemonicLookup(mnemonic=VALID_MNEMONIC, chains=[ETHEREUM])
            result = await lookup.execute(scan_id="test-km-003")
            from src.core.models import Severity

            assert any(f.severity == Severity.CRITICAL for f in result.findings)
            assert result.has_hits is True

    async def test_account_range(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=0.0,
            balance_raw=0,
            usd_price=0.0,
            usd_value=0.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            lookup = KnownMnemonicLookup(
                mnemonic=VALID_MNEMONIC,
                chains=[ETHEREUM],
                account_range=(0, 3),
            )
            result = await lookup.execute(scan_id="test-km-004")
            # 3 account indices * ETH derivation paths
            assert result.addresses_checked == 3 * len(ETHEREUM.derivation_paths)


# --- AccountRangeScan Tests ---


class TestAccountRangeScan:
    def test_invalid_mnemonic_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            AccountRangeScan(mnemonic="not valid", chain=ETHEREUM)

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError, match="end must be greater"):
            AccountRangeScan(mnemonic=VALID_MNEMONIC, chain=ETHEREUM, start=10, end=5)

    async def test_execute_range(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=0.0,
            balance_raw=0,
            usd_price=0.0,
            usd_value=0.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            scanner = AccountRangeScan(
                mnemonic=VALID_MNEMONIC,
                chain=ETHEREUM,
                start=0,
                end=5,
            )
            result = await scanner.execute(scan_id="test-ar-001")
            assert isinstance(result, TargetedScanResult)
            assert result.mode == "account_range"
            assert result.addresses_checked == 5 * len(ETHEREUM.derivation_paths)
            assert "Ethereum" in result.chains_checked

    async def test_with_balance_hit(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=5.0,
            balance_raw=5000000000000000000,
            usd_price=2000.0,
            usd_value=10000.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ),
        ):
            scanner = AccountRangeScan(
                mnemonic=VALID_MNEMONIC,
                chain=ETHEREUM,
                start=0,
                end=2,
            )
            result = await scanner.execute(scan_id="test-ar-002")
            assert result.has_hits is True
            assert len(result.findings) == 2 * len(ETHEREUM.derivation_paths)


# --- FilteredRandomScan Tests ---


class TestFilteredRandomScan:
    def test_init_defaults(self):
        scanner = FilteredRandomScan()
        assert scanner.chains == list(ALL_CHAINS)
        assert scanner.min_balance == 0.0
        assert scanner.derivation_paths is None

    def test_init_custom(self):
        scanner = FilteredRandomScan(chains=[ETHEREUM], min_balance=0.001)
        assert scanner.chains == [ETHEREUM]
        assert scanner.min_balance == 0.001

    async def test_execute_with_mocked_balances(self):
        mock_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=0.0,
            balance_raw=0,
            usd_price=0.0,
            usd_value=0.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=mock_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            scanner = FilteredRandomScan(chains=[ETHEREUM])
            result = await scanner.execute(scan_id="test-fr-001", iterations=3)
            assert isinstance(result, TargetedScanResult)
            assert result.mode == "filtered_random"
            assert result.addresses_checked >= 3

    async def test_filters_by_min_balance(self):
        """Results below min_balance should be filtered out."""
        low_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=0.0001,
            balance_raw=100000000000000,
            usd_price=0.0,
            usd_value=0.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=low_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            scanner = FilteredRandomScan(chains=[ETHEREUM], min_balance=1.0)
            result = await scanner.execute(scan_id="test-fr-002", iterations=2)
            # Low balance below threshold should be filtered
            assert len(result.findings) == 0

    async def test_includes_above_min_balance(self):
        high_balance = BalanceResult(
            address="0x123",
            chain="Ethereum",
            symbol="ETH",
            balance=5.0,
            balance_raw=5000000000000000000,
            usd_price=2000.0,
            usd_value=10000.0,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with (
            patch(
                "src.modules.crypto.balance.targeted_search.check_balance",
                new_callable=AsyncMock,
                return_value=high_balance,
            ),
            patch(
                "src.modules.crypto.balance.targeted_search.get_usd_prices",
                new_callable=AsyncMock,
                return_value={"ethereum": 2000.0},
            ),
        ):
            scanner = FilteredRandomScan(chains=[ETHEREUM], min_balance=1.0)
            result = await scanner.execute(scan_id="test-fr-003", iterations=1)
            assert len(result.findings) >= 1
            assert result.has_hits is True
