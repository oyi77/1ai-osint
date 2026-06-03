"""Telegram channel scanner using Telethon for crypto key leak discovery.

Two-tier approach:
- Tier 1: Monitor channels the bot is already in (zero setup)
- Tier 2: Auto-discover new channels via keyword search

Requires TELEGRAM_API_ID and TELEGRAM_API_HASH in environment.
Session persisted to .omc/telegram.session for headless operation.

Usage:
    scanner = TelethonLeakScanner()
    await scanner.connect()
    findings = await scanner.scan_channels(["@crypto_leaks_channel"])
    await scanner.disconnect()
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.modules.crypto.balance._leak_shared import (
    LeakFinding,
    MnemonicPatternDetector,
)
from src.modules.crypto.privatekey.scanner import detect_key_format

logger = logging.getLogger(__name__)

# Default channels to seed the scanner
SEED_CHANNELS = [
    "leaked_wallets",
    "crypto_leaks",
    "wallet_dumps",
    "seed_phrase_leak",
    "private_keys_dump",
]

# Keywords for channel auto-discovery
DISCOVERY_KEYWORDS = [
    "crypto leak",
    "wallet dump",
    "seed phrase",
    "private key",
    "mnemonic leak",
    "wallet private",
]


@dataclass
class TelegramMessage:
    """Parsed Telegram message."""

    channel: str
    message_id: int
    text: str
    date: datetime
    sender_id: Optional[int] = None


class TelethonLeakScanner:
    """Telegram scanner using Telethon for passive channel monitoring.

    Uses user account API (not bot API) to monitor public channels.
    Session persisted to disk for headless VPS operation.
    """

    def __init__(
        self,
        api_id: Optional[int] = None,
        api_hash: Optional[str] = None,
        session_path: str = ".omc/telegram",
        hit_logger=None,
    ):
        self.api_id = api_id or int(os.environ.get("TELEGRAM_API_ID", "0"))
        self.api_hash = api_hash or os.environ.get("TELEGRAM_API_HASH", "")
        self.session_path = session_path
        self.hit_logger = hit_logger
        self._client = None
        self._connected = False

    async def connect(self) -> bool:
        """Connect to Telegram. Returns True on success."""
        try:
            from telethon import TelegramClient
        except ImportError:
            logger.warning("telethon not installed: pip install telethon")
            return False

        if not self.api_id or not self.api_hash:
            logger.warning("TELEGRAM_API_ID/TELEGRAM_API_HASH not set")
            return False

        try:
            self._client = TelegramClient(self.session_path, self.api_id, self.api_hash)
            await self._client.connect()
            if not await self._client.is_user_authorized():
                logger.warning(
                    "Telegram session not authorized. Run: "
                    "python -c 'import asyncio; from src.modules.crypto.balance.leak_scanner_telegram import TelethonLeakScanner; asyncio.run(TelethonLeakScanner().interactive_auth())'"
                )
                return False
            self._connected = True
            logger.info("Connected to Telegram")
            return True
        except Exception as e:
            logger.error("Telegram connection failed: %s", e)
            return False

    async def interactive_auth(self, phone: str = None):
        """Interactive auth flow for initial setup. Run once manually."""
        try:
            from telethon import TelegramClient
        except ImportError:
            print("Install telethon: pip install telethon")
            return

        if not phone:
            phone = input("Phone number (international format): ")

        client = TelegramClient(self.session_path, self.api_id, self.api_hash)
        await client.start(phone=phone)
        print(f"Authorized as: {await client.get_me()}")
        await client.disconnect()

    async def disconnect(self):
        """Disconnect from Telegram."""
        if self._client and self._connected:
            await self._client.disconnect()
            self._connected = False

    async def scan_channels(
        self, channel_usernames: list[str], limit: int = 200
    ) -> list[LeakFinding]:
        """Scan specified channels for leaked keys.

        Args:
            channel_usernames: List of channel usernames (without @)
            limit: Max messages per channel

        Returns:
            List of LeakFinding with detected keys/mnemonics
        """
        if not self._connected:
            if not await self.connect():
                return []

        findings = []
        for channel in channel_usernames:
            try:
                ch_findings = await self._scan_single_channel(channel, limit)
                findings.extend(ch_findings)
                await asyncio.sleep(2)  # Rate limit between channels
            except Exception as e:
                logger.warning("Failed to scan channel %s: %s", channel, e)

        return findings

    async def _scan_single_channel(self, channel: str, limit: int) -> list[LeakFinding]:
        """Scan a single channel for keys in text AND document attachments."""
        findings = []
        try:
            entity = await self._client.get_entity(channel)
            async for message in self._client.iter_messages(entity, limit=limit):
                # Scan message text
                if message.text:
                    self._extract_from_text(message.text, channel, message.id, findings)

                # Scan document attachments (text/plain, .txt files)
                if message.document and hasattr(message.document, "mime_type"):
                    mime = message.document.mime_type or ""
                    size = (
                        message.document.size
                        if hasattr(message.document, "size")
                        else 0
                    )
                    if (
                        "text" in mime or "json" in mime
                    ) and size < 500_000:  # Max 500KB
                        try:
                            data = await self._client.download_media(message, bytes)
                            if data:
                                text = data.decode("utf-8", errors="ignore")
                                self._extract_from_text(
                                    text, channel, message.id, findings
                                )
                                del data  # Free memory immediately
                        except Exception as e:
                            logger.debug("Document download error: %s", e)

        except Exception as e:
            logger.debug("Channel %s error: %s", channel, e)

        return findings

    def _extract_from_text(
        self, text: str, channel: str, message_id: int, findings: list
    ):
        """Extract keys and mnemonics from text, append to findings."""
        # Check for private keys
        keys = detect_key_format(text)
        for k in keys:
            if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                findings.append(
                    LeakFinding(
                        source="telegram",
                        source_url=f"https://t.me/{channel}/{message_id}",
                        mnemonic_candidate=k["match"],
                        is_valid=False,
                    )
                )

        # Check for mnemonics
        candidates = MnemonicPatternDetector.find_mnemonics(text)
        for c in candidates:
            findings.append(
                LeakFinding(
                    source="telegram",
                    source_url=f"https://t.me/{channel}/{message_id}",
                    mnemonic_candidate=c,
                    is_valid=True,
                )
            )

    async def discover_channels(
        self, keywords: Optional[list[str]] = None, max_channels: int = 20
    ) -> list[str]:
        """Auto-discover Telegram channels matching crypto leak keywords.

        Args:
            keywords: Search keywords (defaults to DISCOVERY_KEYWORDS)
            max_channels: Maximum channels to return

        Returns:
            List of channel usernames
        """
        if not self._connected:
            if not await self.connect():
                return []

        keywords = keywords or DISCOVERY_KEYWORDS
        found = set()

        for kw in keywords:
            try:
                result = await self._client.get_dialogs(limit=50)
                # Search in joined dialogs
                for dialog in result:
                    if dialog.is_channel and dialog.name:
                        name_lower = dialog.name.lower()
                        if any(
                            k in name_lower
                            for k in ["leak", "dump", "wallet", "seed", "key", "crypto"]
                        ):
                            if (
                                dialog.entity
                                and hasattr(dialog.entity, "username")
                                and dialog.entity.username
                            ):
                                found.add(dialog.entity.username)

                # Use global search
                from telethon.tl.functions.contacts import SearchRequest

                search_result = await self._client(SearchRequest(q=kw, limit=10))
                for chat in search_result.chats:
                    if hasattr(chat, "username") and chat.username:
                        found.add(chat.username)

                await asyncio.sleep(3)  # Rate limit
            except Exception as e:
                logger.debug("Discovery search '%s' failed: %s", kw, e)

        return list(found)[:max_channels]

    async def search_messages(
        self, query: str, limit: int = 50
    ) -> list[TelegramMessage]:
        """Search across joined channels for messages matching query.

        Useful for reverse lookup: search for a specific address.
        """
        if not self._connected:
            if not await self.connect():
                return []

        messages = []
        try:
            # Search in all dialogs
            async for message in self._client.iter_messages(
                None, search=query, limit=limit
            ):
                if message.text:
                    channel = ""
                    if message.chat and hasattr(message.chat, "username"):
                        channel = message.chat.username or ""
                    messages.append(
                        TelegramMessage(
                            channel=channel,
                            message_id=message.id,
                            text=message.text,
                            date=message.date or datetime.now(timezone.utc),
                            sender_id=message.sender_id,
                        )
                    )
        except Exception as e:
            logger.debug("Message search '%s' failed: %s", query, e)

        return messages


async def run_telegram_leak_scan(
    channels: Optional[list[str]] = None,
    auto_discover: bool = True,
    hit_logger=None,
) -> list[LeakFinding]:
    """Run a complete Telegram leak scan.

    1. Connect via Telethon
    2. Auto-discover channels if enabled
    3. Scan all channels for keys
    4. Return findings

    Args:
        channels: Specific channels to scan (without @)
        auto_discover: Whether to auto-discover new channels
        hit_logger: Optional hit logger
    """
    scanner = TelethonLeakScanner(hit_logger=hit_logger)

    if not await scanner.connect():
        logger.warning("Telegram connection failed, skipping Telegram scan")
        return []

    all_channels = list(channels or [])

    if auto_discover:
        discovered = await scanner.discover_channels()
        logger.info("Auto-discovered %d channels", len(discovered))
        all_channels.extend(discovered)

    if not all_channels:
        all_channels = SEED_CHANNELS
        logger.info("Using %d seed channels", len(all_channels))

    logger.info("Scanning %d Telegram channels", len(all_channels))
    findings = await scanner.scan_channels(all_channels)

    await scanner.disconnect()

    logger.info("Telegram scan complete: %d findings", len(findings))
    return findings
