"""Holehe source adapter for email account enumeration."""

from __future__ import annotations

import asyncio
import logging

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class HoleheSource:
    """Use holehe to check if an email is registered on various platforms."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Holehe requires an email target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Check if an email is registered on various platforms."""
        leaks: list[RawLeak] = []
        if "@" not in address:
            return leaks

        try:
            from holehe import check_email

            result = await asyncio.wait_for(
                check_email(address),
                timeout=self.timeout,
            )
            if result:
                for site, data in result.items():
                    if data.get("exists"):
                        leaks.append(
                            RawLeak(
                                text=f"Email '{address}' registered on {site}",
                                source_name="holehe",
                                source_url=f"https://{site}",
                            )
                        )
        except ImportError:
            logger.debug("Holehe: package not installed, skipping")
        except asyncio.TimeoutError:
            logger.debug("Holehe: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("Holehe error: %s", exc)

        return leaks
