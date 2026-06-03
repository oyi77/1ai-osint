"""WhatsApp and Telegram presence verification."""

import logging
from typing import Optional
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class MessagingPresence(BaseModel):
    phone_number: str = ""
    whatsapp_registered: Optional[bool] = None  # None = unknown
    telegram_username: str = ""
    telegram_exists: Optional[bool] = None


class MessagingIntel:
    """Check phone/username presence on WhatsApp and Telegram."""

    async def check_whatsapp(self, phone: str) -> Optional[bool]:
        """Check if a phone number is registered on WhatsApp.
        Uses wa.me redirect behavior.
        """
        # Normalize to international format without +
        p = phone.replace("+", "").replace("-", "").replace(" ", "")
        if p.startswith("0"):
            p = "62" + p[1:]  # Indonesian number
        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=False
            ) as client:
                resp = await client.get(f"https://wa.me/{p}")
                # wa.me returns 200 with a page if the number is valid on WhatsApp
                # and 404 or redirect to error if not
                if resp.status_code == 200:
                    return True
                elif resp.status_code in (301, 302):
                    loc = resp.headers.get("location", "")
                    if "send" in loc:
                        return True
                    return False
        except Exception as e:
            logger.debug("WhatsApp check failed for %s: %s", phone, e)
        return None

    async def check_telegram(self, username: str) -> Optional[bool]:
        """Check if a username exists on Telegram."""
        # Clean username
        username = username.lstrip("@")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://t.me/{username}")
                if resp.status_code == 200:
                    # Check if the page has a real profile or is the "join" page
                    text = resp.text.lower()
                    if "tgme_page_title" in text or "tgme_header_title" in text:
                        return True
                    if "join group" in text or "join channel" in text:
                        return True  # It's a group/channel but it exists
                    if "if you have <strong>telegram</strong>" in text:
                        return False  # Generic page
        except Exception as e:
            logger.debug("Telegram check failed for %s: %s", username, e)
        return None

    async def check_all(self, phone: str = "", username: str = "") -> MessagingPresence:
        """Check both WhatsApp and Telegram."""
        result = MessagingPresence(phone_number=phone, telegram_username=username)
        if phone:
            result.whatsapp_registered = await self.check_whatsapp(phone)
        if username:
            result.telegram_exists = await self.check_telegram(username)
        return result
