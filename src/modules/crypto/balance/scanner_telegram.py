"""Telegram Bot API scanner for leaked crypto credentials.

This is the simple Bot-API based scanner. For the Telethon-based scanner
with channel discovery, see leak_scanner_telegram.py.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from src.modules.crypto.balance._leak_shared import (
    LeakFinding,
    MnemonicPatternDetector,
)
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)


class TelegramLeakScanner:
    """Telegram channel scanner for leaked crypto credentials.

    Uses the Telegram Bot API (via getUpdates) to receive and scan
    forwarded messages from known crypto leak channels.

    Requires TELEGRAM_BOT_TOKEN in environment. Falls back gracefully
    if not configured or if the bot lacks channel access.
    """

    def __init__(
        self,
        bot_token: Optional[str] = None,
        channel_ids: Optional[list[str]] = None,
        hit_logger: Optional[HitLogger] = None,
    ):
        self.bot_token = bot_token or ""
        self.channel_ids = channel_ids or []
        self.hit_logger = hit_logger
        self._last_update_id: int = 0

    async def scan(self, max_messages: int = 100) -> list[LeakFinding]:
        """Scan Telegram updates for leaked mnemonics and private keys.

        Uses getUpdates to fetch recent messages the bot has access to.
        Scans each message for mnemonic phrases and private keys.

        Args:
            max_messages: Maximum messages to process.

        Returns:
            List of LeakFinding objects with candidates.
        """
        if not self.bot_token:
            logger.info("Telegram bot token not configured — skipping Telegram scan")
            return []

        findings = []
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                updates = await self._get_updates(client, max_messages)
                for update in updates:
                    message = update.get("message", {})
                    text = message.get("text", "")
                    if not text:
                        continue

                    # Check for mnemonics
                    candidates = MnemonicPatternDetector.find_mnemonics(text)
                    if candidates:
                        findings.append(
                            LeakFinding(
                                source="telegram",
                                source_url=f"telegram_msg_{message.get('message_id', '')}",
                                mnemonic_candidate=candidates[0],
                                is_valid=True,
                                source_type="mnemonic",
                            )
                        )
                        continue

                    # Check for private keys
                    from src.modules.crypto.privatekey.scanner import detect_key_format

                    keys = detect_key_format(text)
                    if keys:
                        for k in keys:
                            if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                                findings.append(
                                    LeakFinding(
                                        source="telegram",
                                        source_url=f"telegram_msg_{message.get('message_id', '')}",
                                        mnemonic_candidate=k["match"],
                                        is_valid=False,
                                        source_type="private_key",
                                    )
                                )
                                break
            except Exception as e:
                logger.error("Telegram scan error: %s", e)

        return findings

    async def _get_updates(self, client: httpx.AsyncClient, limit: int) -> list[dict]:
        """Fetch updates from the Telegram Bot API."""
        try:
            resp = await client.get(
                f"https://api.telegram.org/bot{self.bot_token}/getUpdates",
                params={
                    "offset": self._last_update_id + 1,
                    "limit": min(limit, 100),
                    "allowed_updates": '["message"]',
                },
            )
            resp.raise_for_status()
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "Telegram API error: %s", data.get("description", "unknown")
                )
                return []

            updates = data.get("result", [])
            if updates:
                self._last_update_id = updates[-1]["update_id"]
            return updates
        except Exception as e:
            logger.error("Telegram getUpdates error: %s", e)
            return []
