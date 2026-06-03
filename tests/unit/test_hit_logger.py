"""Tests for hit_logger module."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock


class TestWalletHit:
    def test_wallet_hit_defaults(self):
        from src.modules.crypto.balance.hit_logger import WalletHit

        hit = WalletHit(address="0xabc", chain="Ethereum", symbol="ETH", balance=1.5)
        assert hit.address == "0xabc"
        assert hit.chain == "Ethereum"
        assert hit.symbol == "ETH"
        assert hit.balance == 1.5
        assert hit.balance_raw == 0
        assert hit.usd_price == 0.0
        assert hit.usd_value == 0.0
        assert hit.mnemonic_hash == ""
        assert hit.derivation_path == ""
        assert hit.source == "scanner"
        assert hit.found_at  # auto-generated

    def test_wallet_hit_custom_values(self):
        from src.modules.crypto.balance.hit_logger import WalletHit

        hit = WalletHit(
            address="0xdef",
            chain="Polygon",
            symbol="MATIC",
            balance=100.0,
            balance_raw=100_000_000_000_000_000_000,
            usd_price=0.8,
            usd_value=80.0,
            mnemonic_hash="abc123",
            derivation_path="m/44'/60'/0'/0/0",
            source="leak_finder",
            found_at="2024-01-01T00:00:00",
        )
        assert hit.balance_raw == 100_000_000_000_000_000_000
        assert hit.usd_value == 80.0
        assert hit.source == "leak_finder"


class TestHitLoggerInit:
    def test_default_init(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        assert hl._db_path == "wallet_hits.db"
        assert hl._telegram_token is None
        assert hl._telegram_chat_id is None
        assert hl._webhook_url is None
        assert hl._db is None
        assert hl._http is None
        assert hl._buffer == []
        assert hl._closed is False

    def test_custom_init(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(
            db_path="custom.db",
            telegram_token="tok",
            telegram_chat_id="123",
            webhook_url="https://hook.test",
        )
        assert hl._db_path == "custom.db"
        assert hl._telegram_token == "tok"
        assert hl._telegram_chat_id == "123"
        assert hl._webhook_url == "https://hook.test"


class TestHitLoggerLogHit:
    @pytest.mark.asyncio
    async def test_log_hit_buffers(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        # Don't start — just test buffering
        await hl.log_hit(address="0x1", chain="ETH", balance=1.0, usd_value=2000)
        assert len(hl._buffer) == 1
        assert hl._buffer[0]["address"] == "0x1"

    @pytest.mark.asyncio
    async def test_log_hit_strips_private_key(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        await hl.log_hit(
            address="0x1",
            chain="ETH",
            balance=1.0,
            usd_value=2000,
            private_key_hex="DEADBEEF",
        )
        assert len(hl._buffer) == 1
        assert "private_key_hex" not in hl._buffer[0]

    @pytest.mark.asyncio
    async def test_log_hit_multiple(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        for i in range(5):
            await hl.log_hit(
                address=f"0x{i}", chain="ETH", balance=float(i), usd_value=0
            )
        assert len(hl._buffer) == 5


class TestHitLoggerStartClose:
    @pytest.mark.asyncio
    async def test_start_creates_db(self, tmp_path):
        from src.modules.crypto.balance.hit_logger import HitLogger

        db_file = tmp_path / "test_hits.db"
        hl = HitLogger(db_path=str(db_file))
        mock_conn = AsyncMock()
        mock_http = AsyncMock()
        with patch(
            "src.modules.crypto.balance.hit_logger.aiosqlite.connect",
            new_callable=AsyncMock,
            return_value=mock_conn,
        ):
            with patch(
                "src.modules.crypto.balance.hit_logger.httpx.AsyncClient",
                return_value=mock_http,
            ):
                with patch("src.modules.crypto.balance.hit_logger.asyncio.create_task"):
                    await hl.start()
        assert hl._db is mock_conn
        mock_conn.executescript.assert_called_once()
        hl._flush_task = None  # skip awaiting the mock task
        await hl.close()

    @pytest.mark.asyncio
    async def test_close_flushes(self, tmp_path):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(db_path=str(tmp_path / "test.db"))
        mock_db = AsyncMock()
        hl._db = mock_db
        hl._http = AsyncMock()
        hl._closed = False
        # Put something in buffer
        hl._buffer.append(
            {"address": "0x1", "chain": "ETH", "balance": 0, "usd_value": 0}
        )
        await hl.close()
        assert hl._closed is True
        mock_db.close.assert_called_once()


class TestHitLoggerFlush:
    @pytest.mark.asyncio
    async def test_flush_writes_to_db(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        mock_db = AsyncMock()
        hl._db = mock_db
        hl._buffer = [
            {"address": "0x1", "chain": "ETH", "balance": 1.0, "usd_value": 2000},
            {"address": "0x2", "chain": "SOL", "balance": 0.0, "usd_value": 0},
        ]
        await hl.flush()
        mock_db.executemany.assert_called_once()
        mock_db.commit.assert_called_once()
        assert len(hl._buffer) == 0

    @pytest.mark.asyncio
    async def test_flush_empty_buffer(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        mock_db = AsyncMock()
        hl._db = mock_db
        hl._buffer = []
        await hl.flush()
        mock_db.executemany.assert_not_called()

    @pytest.mark.asyncio
    async def test_flush_no_db(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        hl._buffer = [{"address": "0x1"}]
        hl._db = None
        # Should not raise
        await hl.flush()

    @pytest.mark.asyncio
    async def test_flush_db_error_restores_buffer(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        mock_db = AsyncMock()
        mock_db.executemany.side_effect = Exception("db error")
        hl._db = mock_db
        hl._buffer = [{"address": "0x1", "chain": "ETH", "balance": 0, "usd_value": 0}]
        await hl.flush()
        # Buffer should be restored on failure
        assert len(hl._buffer) == 1


class TestHitLoggerQueryRecent:
    @pytest.mark.asyncio
    async def test_query_recent_returns_rows(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        mock_db = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(
            return_value=[
                (
                    "0x1",
                    "ETH",
                    1.0,
                    2000.0,
                    "hash1",
                    "m/44'/60'",
                    "2024-01-01",
                    "scanner",
                ),
            ]
        )
        mock_db.execute = AsyncMock(return_value=mock_cursor)
        hl._db = mock_db
        result = await hl.query_recent(limit=10)
        assert len(result) == 1
        assert result[0]["address"] == "0x1"
        assert result[0]["chain"] == "ETH"

    @pytest.mark.asyncio
    async def test_query_recent_no_db(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger()
        result = await hl.query_recent()
        assert result == []


class TestHitLoggerAlert:
    @pytest.mark.asyncio
    async def test_alert_sends_telegram(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(telegram_token="tok", telegram_chat_id="123")
        mock_http = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        hl._http = mock_http
        hit = {"address": "0x1", "chain": "ETH", "balance": 1.5, "usd_value": 3000}
        await hl._send_telegram(hit)
        mock_http.post.assert_called_once()
        call_args = mock_http.post.call_args
        assert "tok" in call_args[0][0]
        assert call_args[1]["json"]["chat_id"] == "123"

    @pytest.mark.asyncio
    async def test_alert_sends_webhook(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(webhook_url="https://hook.test")
        mock_http = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        hl._http = mock_http
        hit = {"address": "0x1", "chain": "ETH", "balance": 1.0, "usd_value": 2000}
        await hl._send_webhook(hit)
        mock_http.post.assert_called_once_with("https://hook.test", json=hit)

    @pytest.mark.asyncio
    async def test_webhook_strips_private_key(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(webhook_url="https://hook.test")
        mock_http = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        hl._http = mock_http
        hit = {
            "address": "0x1",
            "chain": "ETH",
            "balance": 1.0,
            "private_key_hex": "DEAD",
        }
        await hl._send_webhook(hit)
        sent_payload = mock_http.post.call_args[1]["json"]
        assert "private_key_hex" not in sent_payload

    @pytest.mark.asyncio
    async def test_send_telegram_no_http(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(telegram_token="tok", telegram_chat_id="123")
        hl._http = None
        # Should not raise
        await hl._send_telegram({"address": "0x1"})

    @pytest.mark.asyncio
    async def test_send_webhook_no_http(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        hl = HitLogger(webhook_url="https://hook.test")
        hl._http = None
        # Should not raise
        await hl._send_webhook({"address": "0x1"})


class TestHitLoggerHashMnemonic:
    def test_hash_mnemonic(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        h1 = HitLogger.hash_mnemonic("abandon abandon abandon")
        h2 = HitLogger.hash_mnemonic("abandon abandon abandon")
        h3 = HitLogger.hash_mnemonic("different phrase")
        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 64  # SHA-256 hex

    def test_hash_mnemonic_strips_whitespace(self):
        from src.modules.crypto.balance.hit_logger import HitLogger

        h1 = HitLogger.hash_mnemonic("  phrase  ")
        h2 = HitLogger.hash_mnemonic("phrase")
        assert h1 == h2
