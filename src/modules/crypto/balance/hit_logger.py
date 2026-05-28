"""Async hit logger for wallet balance discoveries.

Uses aiosqlite for non-blocking database writes and sends alerts via
Telegram bot and/or webhook for significant balance hits.  Batches inserts
(every 10 hits or every 5 seconds) to reduce write contention.

IMPORTANT: Private keys are NEVER stored.  Any ``private_key_hex`` field
is stripped before persistence or alerting.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite
import httpx

from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class WalletHit:
    """A confirmed wallet balance hit for logging and alerting."""
    address: str
    chain: str
    symbol: str
    balance: float
    balance_raw: int = 0
    usd_price: float = 0.0
    usd_value: float = 0.0
    mnemonic_hash: str = ""
    derivation_path: str = ""
    source: str = "scanner"
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


_BATCH_SIZE = 10
_FLUSH_INTERVAL_S = 5.0
_TELEGRAM_TIMEOUT = 10

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS wallet_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    chain TEXT NOT NULL,
    balance REAL NOT NULL,
    usd_value REAL NOT NULL,
    mnemonic_hash TEXT,
    derivation_path TEXT,
    found_at TEXT NOT NULL,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_wallet_hits_address ON wallet_hits(address);
CREATE INDEX IF NOT EXISTS idx_wallet_hits_chain ON wallet_hits(chain);
CREATE INDEX IF NOT EXISTS idx_wallet_hits_found_at ON wallet_hits(found_at);
"""


class HitLogger:
    """Async logger for wallet hits with batched SQLite writes and alerting.

    Buffers incoming hits and flushes to SQLite every ``batch_size`` hits or
    ``flush_interval_s`` seconds, whichever comes first.  Alerts are
    dispatched via Telegram bot and/or webhook for each hit with balance > 0.

    Usage::

        hit_logger = HitLogger(
            db_path="hits.db",
            telegram_token="...", telegram_chat_id="123",
            webhook_url="https://example.com/hook",
        )
        await hit_logger.start()
        await hit_logger.log_hit(address="0x...", chain="Ethereum", balance=1.5, usd_value=3000)
        await hit_logger.close()
    """

    def __init__(
        self,
        db_path: str = "wallet_hits.db",
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        webhook_url: Optional[str] = None,
    ) -> None:
        self._db_path = db_path
        self._telegram_token = telegram_token
        self._telegram_chat_id = telegram_chat_id
        self._webhook_url = webhook_url
        self._db: Optional[aiosqlite.Connection] = None
        self._http: Optional[httpx.AsyncClient] = None
        self._buffer: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._closed = False

    async def start(self) -> None:
        """Initialize the database connection, create tables, start flush loop."""
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.executescript(_CREATE_TABLE_SQL)
        self._http = httpx.AsyncClient(timeout=_TELEGRAM_TIMEOUT)
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("HitLogger started, db=%s", self._db_path)

    async def close(self) -> None:
        """Flush remaining hits and close all resources."""
        self._closed = True
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()
        if self._http:
            await self._http.aclose()
            self._http = None
        if self._db:
            await self._db.close()
            self._db = None

    async def log_hit(self, **kwargs: Any) -> None:
        """Buffer a wallet hit.  Private keys are stripped automatically.

        Keyword args: address, chain, balance, usd_value, mnemonic_hash
        (optional), derivation_path (optional), source (optional).
        Any ``private_key_hex`` key is silently removed.
        """
        # CRITICAL: never store private keys
        clean = {k: v for k, v in kwargs.items() if k != "private_key_hex"}
        async with self._lock:
            self._buffer.append(clean)
            if len(self._buffer) >= _BATCH_SIZE:
                await self._flush_internal()

    async def flush(self) -> None:
        """Force-flush all buffered hits to the database."""
        async with self._lock:
            await self._flush_internal()

    async def query_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Read recent hits from the database."""
        if not self._db:
            return []
        cursor = await self._db.execute(
            "SELECT address, chain, balance, usd_value, mnemonic_hash, "
            "derivation_path, found_at, source "
            "FROM wallet_hits ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "address": r[0], "chain": r[1], "balance": r[2],
                "usd_value": r[3], "mnemonic_hash": r[4],
                "derivation_path": r[5], "found_at": r[6], "source": r[7],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _flush_loop(self) -> None:
        """Periodic flush every _FLUSH_INTERVAL_S seconds."""
        while not self._closed:
            await asyncio.sleep(_FLUSH_INTERVAL_S)
            async with self._lock:
                await self._flush_internal()

    async def _flush_internal(self) -> None:
        """Write buffered hits to SQLite and send alerts (caller holds lock)."""
        if not self._buffer or not self._db:
            return

        batch = list(self._buffer)
        self._buffer.clear()

        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                h.get("address", ""),
                h.get("chain", ""),
                float(h.get("balance", 0)),
                float(h.get("usd_value", 0)),
                h.get("mnemonic_hash"),
                h.get("derivation_path"),
                now,
                h.get("source", ""),
            )
            for h in batch
        ]

        try:
            await self._db.executemany(
                "INSERT INTO wallet_hits "
                "(address, chain, balance, usd_value, mnemonic_hash, "
                "derivation_path, found_at, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            await self._db.commit()
            logger.debug("Flushed %d wallet hits to database", len(batch))
        except Exception:
            logger.exception("Failed to flush hits to SQLite")
            self._buffer = batch + self._buffer
            return

        # Send alerts for hits with balance > 0
        alerts = [h for h in batch if float(h.get("balance", 0)) > 0]
        for hit in alerts:
            await self._alert(hit)

    async def _alert(self, hit: dict[str, Any]) -> None:
        """Dispatch Telegram and webhook alerts for a hit."""
        tasks: list[asyncio.Task] = []
        if self._telegram_token and self._telegram_chat_id:
            tasks.append(asyncio.create_task(self._send_telegram(hit)))
        if self._webhook_url:
            tasks.append(asyncio.create_task(self._send_webhook(hit)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_telegram(self, hit: dict[str, Any]) -> None:
        """Send a Telegram bot message for a hit."""
        if not self._http:
            return
        text = (
            f"{hit.get('chain', '?')} | {hit.get('address', '?')} | "
            f"{float(hit.get('balance', 0)):.8f} "
            f"(~${float(hit.get('usd_value', 0)):,.2f})"
        )
        url = (
            f"https://api.telegram.org/bot"
            f"{self._telegram_token}/sendMessage"
        )
        payload = {
            "chat_id": self._telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
        }
        try:
            resp = await self._http.post(url, json=payload)
            resp.raise_for_status()
            logger.debug("Telegram alert sent for %s", hit.get("address"))
        except Exception as e:
            logger.warning("Telegram alert failed for %s: %s", hit.get("address"), e)

    async def _send_webhook(self, hit: dict[str, Any]) -> None:
        """POST hit data to a webhook endpoint."""
        if not self._http:
            return
        # private_key_hex already stripped in log_hit, but double-check
        payload = {k: v for k, v in hit.items() if k != "private_key_hex"}
        try:
            resp = await self._http.post(self._webhook_url, json=payload)
            resp.raise_for_status()
            logger.debug("Webhook alert sent for %s", hit.get("address"))
        except Exception as e:
            logger.warning("Webhook alert failed: %s", e)

    @staticmethod
    def hash_mnemonic(mnemonic: str) -> str:
        """Return a SHA-256 hash of a mnemonic phrase for storage."""
        return hashlib.sha256(mnemonic.strip().encode("utf-8")).hexdigest()
