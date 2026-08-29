"""Carrier / line-type source via the omkarcloud Phone Lookup API.

Complements GetContact (profile + tags) with network-level data: carrier,
line type (mobile/landline/VoIP), validity, country and national formatting.
Free tier: ~200 lookups/month. Configure the API key via env
OMKAR_PHONE_API_KEY. Key-gated: without a key this source is skipped.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_ENDPOINT = "https://carrier-lookup-api.omkar.cloud/lookup"


class PhoneCarrierLookup:
    """Carrier/line-type lookup via the omkarcloud Phone Lookup API."""

    def __init__(self, api_key: str | None = None, timeout: float = 15.0):
        self.api_key = api_key or os.environ.get("OMKAR_PHONE_API_KEY", "")
        self.timeout = timeout

    @property
    def available(self) -> bool:
        """Key-gated: only usable when an API key is configured."""
        return bool(self.api_key)

    async def lookup(self, phone: str) -> dict[str, Any] | None:
        """Return carrier info for an E.164 phone, or None on failure/skip."""
        if not self.available:
            return None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    _API_ENDPOINT,
                    params={"phone": phone},
                    headers={"API-Key": self.api_key},
                )
                resp.raise_for_status()
                data = resp.json()
            if data.get("is_valid_number") is False:
                return {"valid": False, "phone": phone}
            return data
        except httpx.HTTPError as e:
            logger.debug("carrier lookup %s failed: %s", phone, e)
            return None
