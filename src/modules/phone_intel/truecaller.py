"""Truecaller phone lookup (unofficial, gated, fragile).

Truecaller has NO public API. This module uses the undocumented mobile/web
endpoint which requires a Bearer token from a logged-in Truecaller account.
The token format and endpoint may change without notice. Use at your own risk.

This source is OPTIONAL and gated: configure env TRUECALLER_TOKEN (and
optionally TRUECALLER_COUNTRY_CODE, default ID). Without the token, this
source is silently skipped.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_ENDPOINT = "https://search5-noneu.truecaller.com/v2/search"
_DEFAULT_COUNTRY = "ID"


class TruecallerLookup:
    """Truecaller phone lookup (unofficial — needs a Bearer token)."""

    def __init__(
        self,
        token: str | None = None,
        country_code: str | None = None,
        timeout: float = 15.0,
    ):
        self.token = token or os.environ.get("TRUECALLER_TOKEN", "")
        self.country_code = country_code or os.environ.get("TRUECALLER_COUNTRY_CODE", _DEFAULT_COUNTRY)
        self.timeout = timeout

    @property
    def available(self) -> bool:
        """Gated: only usable when a Bearer token is configured."""
        return bool(self.token)

    async def lookup(self, phone: str) -> dict[str, Any] | None:
        """Look up a phone number on Truecaller. Returns profile data or None."""
        if not self.available:
            return None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    _API_ENDPOINT,
                    json={
                        "q": phone,
                        "countryCode": self.country_code,
                        "type": 4,
                        "locAddr": "",
                        "placement": "SEARCHRESULTS",
                        "encoding": "json",
                    },
                    headers={
                        "Authorization": f"Bearer {self.token}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code in (401, 403):
                    logger.warning("Truecaller token expired or invalid (HTTP %d)", resp.status_code)
                return None
        except httpx.HTTPError as e:
            logger.debug("Truecaller lookup %s failed: %s", phone, e)
            return None
