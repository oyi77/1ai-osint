"""WhatsApp OSINT — presence always, status/photo when a session token exists.

The free wa.me check is always available (is this number on WhatsApp?).
Profile data (status text, profile photo, business profile) requires an
unofficial WhatsApp Web session token — gate with env WHATSAPP_WEB_TOKEN.
Without the token, only presence is reported. This mirrors the approach used
by HackUnderway/WhatsOSINT and is equally unofficial/fragile.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_PRESENCE_URL = "https://wa.me/{number}"
# Unofficial WhatsApp Web profile endpoint (gated; may change without notice).
_PROFILE_URL = "https://web.whatsapp.com/api/v1/contact_profile"


class WhatsAppOSINT:
    """WhatsApp presence + (token-gated) profile OSINT."""

    def __init__(self, token: str | None = None, timeout: float = 12.0):
        self.token = token or os.environ.get("WHATSAPP_WEB_TOKEN", "")
        self.timeout = timeout

    @property
    def profile_available(self) -> bool:
        return bool(self.token)

    async def check_presence(self, phone: str) -> bool | None:
        """True if the number is reachable on WhatsApp (wa.me redirect check)."""
        p = phone.replace("+", "").replace("-", "").replace(" ", "")
        if p.startswith("0"):
            p = "62" + p[1:]
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                resp = await client.get(_PRESENCE_URL.format(number=p))
                if resp.status_code == 200:
                    return True
                if resp.status_code in (301, 302):
                    return "send" in resp.headers.get("location", "")
                return False
        except httpx.HTTPError as e:
            logger.debug("WhatsApp presence %s failed: %s", phone, e)
            return None

    async def get_profile(self, phone: str) -> dict[str, Any] | None:
        """Unofficial profile lookup (status, photo, business). Gated."""
        if not self.profile_available:
            return None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    _PROFILE_URL,
                    params={"phone": phone},
                    headers={"Authorization": f"Bearer {self.token}"},
                )
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code in (401, 403):
                    logger.warning("WhatsApp web token expired/invalid (HTTP %d)", resp.status_code)
                return None
        except httpx.HTTPError as e:
            logger.debug("WhatsApp profile %s failed: %s", phone, e)
            return None

    async def lookup(self, phone: str) -> dict[str, Any]:
        """Combined lookup: presence + (gated) profile."""
        result: dict[str, Any] = {"phone": phone}
        result["presence"] = await self.check_presence(phone)
        if self.profile_available:
            profile = await self.get_profile(phone)
            result["profile"] = profile or {}
        else:
            result["profile"] = {}
        return result
