"""Telegram source adapter for crypto leak discovery."""
from __future__ import annotations
import asyncio, logging, os, re
from typing import Optional
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

logger = logging.getLogger(__name__)

_KEY_HINTS_RE = re.compile(r"(?i)(private[_\s-]*key|secret[_\s-]*key|mnemonic|seed[_\s-]*phrase|wallet|0x[0-9a-fA-F]{40,}|[5KL][1-9A-HJ-NP-Za-km-z]{50,51}|[0-9a-fA-F]{64})")

class TelegramSource:
    def __init__(self, api_id: Optional[int] = None, api_hash: Optional[str] = None, session_name: str = "leak_finder", max_messages_per_channel: int = 100, timeout: float = 30.0):
        self.api_id = api_id or int(os.getenv("TELEGRAM_API_ID", "0"))
        self.api_hash = api_hash or os.getenv("TELEGRAM_API_HASH", "")
        self.session_name = session_name
        self.max_messages_per_channel = max_messages_per_channel
        self.timeout = timeout

    async def fetch_raw_leaks(self, keywords: Optional[list[str]] = None, max_channels: int = 10) -> list[RawLeak]:
        try:
            from telethon import TelegramClient
        except ImportError:
            logger.warning("telethon not installed; skipping Telegram scan")
            return []
        if not self.api_id or not self.api_hash:
            return []
        client = TelegramClient(self.session_name, self.api_id, self.api_hash)
        await client.start()
        leaks: list[RawLeak] = []
        keywords = keywords or ["crypto leak", "wallet dump", "seed phrase", "private key leak", "mnemonic leak"]
        try:
            channels = []
            for kw in keywords:
                if len(channels) >= max_channels:
                    break
                try:
                    from telethon.tl.functions.contacts import SearchRequest
                    result = await client(SearchRequest(q=kw, limit=10))
                    for chat in result.chats:
                        if len(channels) >= max_channels:
                            break
                        if chat.id not in [c["id"] for c in channels]:
                            channels.append({"id": chat.id, "title": getattr(chat, "title", ""), "username": getattr(chat, "username", "")})
                    await asyncio.sleep(2)
                except Exception as exc:
                    if "flood" in str(exc).lower():
                        await asyncio.sleep(self._extract_flood_wait(str(exc)) + 1)
            for channel in channels:
                try:
                    entity = await client.get_entity(channel.get("username") or channel["id"])
                    async for message in client.iter_messages(entity, limit=self.max_messages_per_channel):
                        text = message.text or ""
                        if text and _KEY_HINTS_RE.search(text):
                            ref = channel.get("username") or str(channel["id"])
                            leaks.append(RawLeak(text=text, source_name="telegram", source_url=f"https://t.me/{ref}/{message.id}"))
                except Exception as exc:
                    if "flood" in str(exc).lower():
                        await asyncio.sleep(self._extract_flood_wait(str(exc)) + 1)
        finally:
            await client.disconnect()
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        pattern = re.compile(re.escape(address), re.IGNORECASE)
        return [leak for leak in await self.fetch_raw_leaks() if pattern.search(leak.text)]

    @staticmethod
    def _extract_flood_wait(error_msg: str) -> int:
        match = re.search(r"(\d+)\s*seconds?", error_msg)
        if match:
            return int(match.group(1))
        match = re.search(r"wait\s*(\d+)", error_msg, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return 60
