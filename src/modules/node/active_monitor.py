"""Active Telegram & Discord Channel Daemon for threat intelligence scraping."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional, Set

# Regexes for entity extraction
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_REGEX = re.compile(r"\+?[0-9]{10,15}")
ETH_KEY_REGEX = re.compile(r"0x[0-9a-fA-F]{64}")

logger = logging.getLogger(__name__)


class ActiveMonitorDaemon:
    """Active daemon monitoring Telegram and Discord feeds for leaked credentials."""

    def __init__(
        self,
        watchlist_hashes: Optional[Set[str]] = None,
        db_path: str = "state/monitor.db",
        zkit_salt: str = "default-salt",
    ):
        self.watchlist = watchlist_hashes or set()
        self.db_path = db_path
        self.zkit_salt = zkit_salt
        self.is_running = False
        self._tasks: list[asyncio.Task] = []
        self.findings_log: list[dict] = []

    def add_to_watchlist(self, target_value: str) -> str:
        """Hash and add a target value to the watchlist."""
        h = self.hash_value(target_value)
        self.watchlist.add(h)
        return h

    def hash_value(self, val: str) -> str:
        """Helper to generate ZKIT salted SHA-256 hash of an attribute."""
        import hashlib

        preimage = f"{self.zkit_salt}:{val.strip().lower()}".encode("utf-8")
        return hashlib.sha256(preimage).hexdigest()

    async def start(self) -> None:
        """Start the background monitoring streams."""
        if self.is_running:
            return
        self.is_running = True
        logger.info("Starting Active Monitor Daemon...")

        # Spawn Telegram and Discord stream processors
        self._tasks.append(asyncio.create_task(self._monitor_telegram_stream()))
        self._tasks.append(asyncio.create_task(self._monitor_discord_stream()))

    async def stop(self) -> None:
        """Stop all background monitoring streams."""
        self.is_running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Active Monitor Daemon stopped.")

    async def process_raw_message(self, text: str, source: str) -> list[dict]:
        """Extract and check entities in incoming messages against the watchlist."""
        extracted: list[dict] = []

        # Find emails
        for email in EMAIL_REGEX.findall(text):
            h = self.hash_value(email)
            if h in self.watchlist:
                extracted.append({"type": "email", "value": email, "hash": h})

        # Find phones
        for phone in PHONE_REGEX.findall(text):
            h = self.hash_value(phone)
            if h in self.watchlist:
                extracted.append({"type": "phone", "value": phone, "hash": h})

        # Find keys
        for key in ETH_KEY_REGEX.findall(text):
            h = self.hash_value(key)
            if h in self.watchlist:
                extracted.append({"type": "private_key", "value": key, "hash": h})

        # Log findings
        for item in extracted:
            finding = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source,
                "entity_type": item["type"],
                "zkit_hash": item["hash"],
                "message_snippet": text[:100],
            }
            self.findings_log.append(finding)
            logger.warning("WATCHLIST HIT in %s: %s", source, finding)

        return extracted

    async def _monitor_telegram_stream(self) -> None:
        """Background loop simulating Telegram channel monitoring (telethon wrapper fallback)."""
        # Read API credentials (if configured)
        api_id = os.getenv("TELEGRAM_API_ID")
        api_hash = os.getenv("TELEGRAM_API_HASH")

        if api_id and api_hash:
            logger.info("Telegram Telethon listener configured with API_ID: %s", api_id)
            # Under a normal VPS deployment, we would run Telethon Client:
            # client = TelegramClient('session_name', api_id, api_hash)
            # await client.start()
            # @client.on(events.NewMessage) ...

        while self.is_running:
            try:
                # Simulated threat intel channel activity
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                break

    async def _monitor_discord_stream(self) -> None:
        """Background loop simulating Discord channel webhook/bot client feeds."""
        while self.is_running:
            try:
                # Simulated leak server feeds
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                break
