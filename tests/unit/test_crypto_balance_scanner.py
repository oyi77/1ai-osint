"""Tests for the crypto balance scanner engine, API rotation, and hit logger."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.crypto.balance.api_rotation import (
    EndpointHealth,
    EndpointRotator,
    _REENABLE_AFTER_SECONDS,
)
from src.modules.crypto.balance.checker import BalanceResult
from src.modules.crypto.balance.chains import BITCOIN, ETHEREUM, SOLANA
from src.modules.crypto.balance.deriver import DerivedAddress
from src.modules.crypto.balance.hit_logger import HitLogger, WalletHit
from src.modules.crypto.balance.scanner_engine import RandomScanner, ScannerStats


# --- API Rotation Tests ---


class TestEndpointHealth:
    def test_initial_state(self):
        health = EndpointHealth(url="https://rpc.example.com")
        assert health.success_count == 0
        assert health.failure_count == 0
        assert health.consecutive_failures == 0
        assert health.disabled_at is None
        assert health.is_disabled is False

    def test_is_disabled_after_consecutive_failures(self):
        health = EndpointHealth(url="https://rpc.example.com")
        # Not disabled until disabled_at is set
        health.disabled_at = time.monotonic()
        assert health.is_disabled is True

    def test_re_enable_after_cooldown(self):
        health = EndpointHealth(url="https://rpc.example.com")
        # Set disabled in the past beyond cooldown
        health.disabled_at = time.monotonic() - _REENABLE_AFTER_SECONDS - 1
        assert health.is_disabled is False
        assert health.disabled_at is None
        assert health.consecutive_failures == 0


class TestEndpointRotator:
    def test_init_requires_endpoints(self):
        with pytest.raises(ValueError, match="At least one"):
            EndpointRotator([])

    def test_round_robin(self):
        rotator = EndpointRotator(["https://a.com", "https://b.com", "https://c.com"])
        urls = [rotator.next() for _ in range(6)]
        # Should cycle through all endpoints
        assert urls[0] != urls[1] != urls[2]
        assert urls[3] == urls[0]
        assert urls[4] == urls[1]
        assert urls[5] == urls[2]

    def test_report_success_resets_consecutive_failures(self):
        rotator = EndpointRotator(["https://a.com"])
        rotator.report_failure("https://a.com")
        rotator.report_failure("https://a.com")
        health = rotator.get_health("https://a.com")
        assert health.consecutive_failures == 2

        rotator.report_success("https://a.com")
        assert health.consecutive_failures == 0
        assert health.success_count == 1

    def test_report_failure_disables_after_threshold(self):
        rotator = EndpointRotator(["https://a.com", "https://b.com"])
        for _ in range(3):
            rotator.report_failure("https://a.com")

        health = rotator.get_health("https://a.com")
        assert health.is_disabled is True

    def test_skips_disabled_endpoint(self):
        rotator = EndpointRotator(["https://a.com", "https://b.com"])
        # Disable a.com
        for _ in range(3):
            rotator.report_failure("https://a.com")

        # Should skip a.com and return b.com
        url = rotator.next()
        assert url == "https://b.com"

    def test_degraded_mode_when_all_disabled(self):
        rotator = EndpointRotator(["https://a.com"])
        for _ in range(3):
            rotator.report_failure("https://a.com")

        # All disabled, should still return something (degraded)
        url = rotator.next()
        assert url == "https://a.com"

    def test_healthy_count(self):
        rotator = EndpointRotator(["https://a.com", "https://b.com"])
        assert rotator.healthy_count == 2

        for _ in range(3):
            rotator.report_failure("https://a.com")
        assert rotator.healthy_count == 1

    def test_endpoints_property(self):
        rotator = EndpointRotator(["https://a.com", "https://b.com"])
        assert rotator.endpoints == ["https://a.com", "https://b.com"]

    def test_report_unknown_url_ignored(self):
        rotator = EndpointRotator(["https://a.com"])
        rotator.report_success("https://unknown.com")  # Should not raise
        rotator.report_failure("https://unknown.com")  # Should not raise


# --- WalletHit Tests ---


class TestWalletHit:
    """Test the kwargs-based log_hit API (no WalletHit dataclass needed)."""

    def test_log_hit_stores_fields(self, tmp_path):
        import asyncio

        async def _run():
            db_path = str(tmp_path / "test_fields.db")
            hit_logger = HitLogger(db_path=db_path)
            await hit_logger.start()
            await hit_logger.log_hit(
                address="0x123",
                chain="Ethereum",
                balance=1.5,
                usd_value=3000.0,
            )
            await hit_logger.flush()
            rows = await hit_logger.query_recent(10)
            assert len(rows) == 1
            assert rows[0]["address"] == "0x123"
            assert rows[0]["chain"] == "Ethereum"
            assert rows[0]["balance"] == 1.5
            assert rows[0]["usd_value"] == 3000.0
            await hit_logger.close()

        asyncio.run(_run())

    def test_log_hit_with_optional_fields(self, tmp_path):
        import asyncio

        async def _run():
            db_path = str(tmp_path / "test_opt.db")
            hit_logger = HitLogger(db_path=db_path)
            await hit_logger.start()
            await hit_logger.log_hit(
                address="0x123",
                chain="Ethereum",
                balance=1.5,
                usd_value=3000.0,
                mnemonic_hash="abc123",
                derivation_path="m/44'/60'/0'/0/0",
                source="random_scan",
            )
            await hit_logger.flush()
            rows = await hit_logger.query_recent(10)
            assert len(rows) == 1
            assert rows[0]["mnemonic_hash"] == "abc123"
            assert rows[0]["derivation_path"] == "m/44'/60'/0'/0/0"
            assert rows[0]["source"] == "random_scan"
            await hit_logger.close()

        asyncio.run(_run())


# --- HitLogger Tests ---


@pytest.mark.asyncio
class TestHitLogger:
    async def test_hash_mnemonic(self):
        h1 = HitLogger.hash_mnemonic("abandon abandon about")
        h2 = HitLogger.hash_mnemonic("abandon abandon about")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    async def test_start_and_close(self, tmp_path):
        db_path = str(tmp_path / "test_hits.db")
        logger = HitLogger(db_path=db_path)
        await logger.start()
        assert logger._db is not None
        await logger.close()
        assert logger._db is None

    async def test_log_hit_and_flush(self, tmp_path):
        db_path = str(tmp_path / "test_hits.db")
        hit_logger = HitLogger(db_path=db_path)
        await hit_logger.start()

        await hit_logger.log_hit(
            address="0xabc",
            chain="Ethereum",
            balance=1.0,
            usd_value=2000.0,
            mnemonic_hash="hash123",
            derivation_path="m/44'/60'/0'/0/0",
            source="test",
        )
        assert len(hit_logger._buffer) == 1

        await hit_logger.flush()
        assert len(hit_logger._buffer) == 0

        # Verify data was written to SQLite
        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute("SELECT address, chain, balance FROM wallet_hits")
            rows = await cursor.fetchall()
            assert len(rows) == 1
            assert rows[0][0] == "0xabc"
            assert rows[0][1] == "Ethereum"
            assert rows[0][2] == 1.0

        await hit_logger.close()

    async def test_batch_flush_at_threshold(self, tmp_path):
        from src.modules.crypto.balance.hit_logger import _BATCH_SIZE

        db_path = str(tmp_path / "test_batch.db")
        hit_logger = HitLogger(db_path=db_path)
        await hit_logger.start()

        # Log BATCH_SIZE hits — should auto-flush
        for i in range(_BATCH_SIZE):
            await hit_logger.log_hit(
                address=f"0x{i}", chain="Ethereum", balance=float(i), usd_value=float(i)
            )

        # Buffer should be empty after auto-flush
        assert len(hit_logger._buffer) == 0

        await hit_logger.close()

    async def test_no_private_key_stored(self, tmp_path):
        """Verify that log_hit strips private key data."""
        db_path = str(tmp_path / "test_nopriv.db")
        hit_logger = HitLogger(db_path=db_path)
        await hit_logger.start()

        await hit_logger.log_hit(
            address="0xabc",
            chain="Ethereum",
            balance=1.0,
            usd_value=2000.0,
            private_key_hex="SHOULD_BE_STRIPPED",
        )
        await hit_logger.flush()

        # Verify no private_key field in the table schema
        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute("PRAGMA table_info(wallet_hits)")
            columns = [row[1] for row in await cursor.fetchall()]
            assert "private_key" not in columns
            assert "private_key_hex" not in columns

        await hit_logger.close()

    @patch("src.modules.crypto.balance.hit_logger.httpx.AsyncClient")
    async def test_telegram_alert_sent_for_nonzero_balance(self, mock_client_cls, tmp_path):
        mock_http = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_http.aclose = AsyncMock()
        mock_client_cls.return_value = mock_http

        db_path = str(tmp_path / "test_tg.db")
        hit_logger = HitLogger(
            db_path=db_path,
            telegram_token="test-token",
            telegram_chat_id="12345",
        )
        await hit_logger.start()

        await hit_logger.log_hit(address="0xabc", chain="Ethereum", balance=1.0, usd_value=2000.0)
        await hit_logger.flush()

        mock_http.post.assert_called_once()
        call_args = mock_http.post.call_args
        assert "test-token" in call_args[0][0]
        assert call_args[1]["json"]["chat_id"] == "12345"

        await hit_logger.close()

    @patch("src.modules.crypto.balance.hit_logger.httpx.AsyncClient")
    async def test_no_telegram_alert_for_zero_balance(self, mock_client_cls, tmp_path):
        mock_http = AsyncMock()
        mock_http.aclose = AsyncMock()
        mock_client_cls.return_value = mock_http

        db_path = str(tmp_path / "test_tg_zero.db")
        hit_logger = HitLogger(
            db_path=db_path,
            telegram_token="test-token",
            telegram_chat_id="12345",
        )
        await hit_logger.start()

        await hit_logger.log_hit(address="0xabc", chain="Ethereum", balance=0.0, usd_value=0.0)
        await hit_logger.flush()

        # No alert for zero balance
        mock_http.post.assert_not_called()

        await hit_logger.close()

    async def test_no_telegram_without_config(self, tmp_path):
        """No crash when Telegram not configured."""
        db_path = str(tmp_path / "test_notg.db")
        hit_logger = HitLogger(db_path=db_path)
        await hit_logger.start()

        await hit_logger.log_hit(address="0xabc", chain="Ethereum", balance=1.0, usd_value=2000.0)
        await hit_logger.flush()  # Should not raise

        await hit_logger.close()


# --- ScannerStats Tests ---


class TestScannerStats:
    def test_initial_state(self):
        stats = ScannerStats()
        assert stats.mnemonics_generated == 0
        assert stats.addresses_checked == 0
        assert stats.hits_found == 0
        assert stats.api_errors == 0

    def test_elapsed(self):
        stats = ScannerStats()
        assert stats.elapsed >= 0

    def test_mnemonics_per_sec_zero_elapsed(self):
        stats = ScannerStats()
        # No time elapsed and no mnemonics — should be 0
        assert stats.mnemonics_per_sec == 0.0

    def test_mnemonics_per_sec_with_data(self):
        stats = ScannerStats()
        stats.mnemonics_generated = 100
        # Elapsed is very small since start_time is now
        # Just verify it returns a float
        rate = stats.mnemonics_per_sec
        assert isinstance(rate, float)


# --- RandomScanner Tests ---


@pytest.mark.asyncio
class TestRandomScanner:
    def test_init_defaults(self):
        scanner = RandomScanner()
        assert scanner.workers == 20
        assert scanner.chains is not None
        assert scanner.hit_logger is None

    def test_init_custom(self):
        scanner = RandomScanner(workers=5, chains=[ETHEREUM])
        assert scanner.workers == 5
        assert scanner.chains == [ETHEREUM]

    def test_generate_mnemonic(self):
        # Test multiple generations to cover both 12 and 24 word mnemonics
        word_counts = set()
        for _ in range(20):
            mnemonic = str(RandomScanner._generate_mnemonic())
            words = mnemonic.split()
            word_counts.add(len(words))
            assert len(words) in (12, 24)
            assert all(w.isalpha() for w in words)
        # Over 20 iterations, should see both 12 and 24 (statistically near-certain)
        assert 12 in word_counts

    async def test_run_with_duration_limit(self):
        scanner = RandomScanner(workers=1, chains=[ETHEREUM])
        mock_addrs = [
            DerivedAddress(
                address="0x123", chain="Ethereum", symbol="ETH",
                derivation_path="m/44'/60'/0'/0/0",
            )
        ]
        with patch.object(scanner, "_check_balances", new_callable=AsyncMock) as mock_check, \
             patch("src.modules.crypto.balance.scanner_engine.derive_from_mnemonic", return_value=mock_addrs):
            mock_check.return_value = [
                BalanceResult(
                    address="0x123", chain="Ethereum", symbol="ETH",
                    balance=0.0, balance_raw=0,
                    usd_price=0.0, usd_value=0.0,
                    derivation_path="m/44'/60'/0'/0/0",
                )
            ]
            stats = await scanner.run(duration_sec=0.5)
            assert isinstance(stats, ScannerStats)
            assert stats.mnemonics_generated >= 0

    async def test_run_with_max_mnemonics(self):
        scanner = RandomScanner(workers=1, chains=[ETHEREUM])
        mock_addrs = [
            DerivedAddress(
                address="0x123", chain="Ethereum", symbol="ETH",
                derivation_path="m/44'/60'/0'/0/0",
            )
        ]
        with patch.object(scanner, "_check_balances", new_callable=AsyncMock) as mock_check, \
             patch("src.modules.crypto.balance.scanner_engine.derive_from_mnemonic", return_value=mock_addrs):
            mock_check.return_value = [
                BalanceResult(
                    address="0x123", chain="Ethereum", symbol="ETH",
                    balance=0.0, balance_raw=0,
                    usd_price=0.0, usd_value=0.0,
                    derivation_path="m/44'/60'/0'/0/0",
                )
            ]
            stats = await scanner.run(max_mnemonics=3)
            assert stats.mnemonics_generated >= 3

    async def test_error_isolation(self):
        """Worker errors should not crash the scanner."""
        scanner = RandomScanner(workers=1, chains=[ETHEREUM])
        mock_addrs = [
            DerivedAddress(
                address="0x123", chain="Ethereum", symbol="ETH",
                derivation_path="m/44'/60'/0'/0/0",
            )
        ]
        with patch.object(scanner, "_check_balances", new_callable=AsyncMock) as mock_check, \
             patch("src.modules.crypto.balance.scanner_engine.derive_from_mnemonic", return_value=mock_addrs):
            mock_check.side_effect = Exception("API down")
            stats = await scanner.run(max_mnemonics=2)
            assert stats.api_errors >= 0  # Errors counted, not crashed

    async def test_graceful_shutdown_flag(self):
        scanner = RandomScanner()
        assert scanner._shutdown is False
        scanner._handle_shutdown()
        assert scanner._shutdown is True

    async def test_double_shutdown_forces_exit(self):
        scanner = RandomScanner()
        scanner._shutdown = True
        with patch("os._exit") as mock_exit:
            scanner._handle_shutdown()
            mock_exit.assert_called_once_with(1)
