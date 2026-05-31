"""theHarvester source adapter for email/domain enumeration."""
from __future__ import annotations
import asyncio

import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class TheHarvesterSource:
    """Use theHarvester to find emails, subdomains, and IPs."""

    def __init__(self, timeout: float = 120.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """theHarvester requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search for emails/subdomains associated with a domain."""
        leaks: list[RawLeak] = []
        harvester_path = shutil.which("theHarvester")
        if not harvester_path:
            logger.debug("theHarvester: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                harvester_path, "-d", address, "-b", "all", "-f", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            if stdout:
                text = stdout.decode()
                if text.strip():
                    leaks.append(RawLeak(
                        text=text,
                        source_name="theharvester",
                        source_url="",
                    ))
        except asyncio.TimeoutError:
            logger.debug("theHarvester: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("theHarvester error: %s", exc)

        return leaks
