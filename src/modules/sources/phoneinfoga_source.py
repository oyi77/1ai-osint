"""PhoneInfoga source adapter for phone number OSINT."""
from __future__ import annotations
import asyncio
import json
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class PhoneInfogaSource:
    """Use PhoneInfoga for phone number scanning and OSINT."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """PhoneInfoga requires a phone number target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Scan a phone number using PhoneInfoga."""
        leaks: list[RawLeak] = []
        phoneinfoga_path = shutil.which("phoneinfoga")
        if not phoneinfoga_path:
            logger.debug("PhoneInfoga: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                phoneinfoga_path, "scan", "-n", address, "--json", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            if stdout:
                try:
                    data = json.loads(stdout.decode())
                    leaks.append(RawLeak(
                        text=json.dumps(data, indent=2),
                        source_name="phoneinfoga",
                        source_url="",
                    ))
                except json.JSONDecodeError:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(RawLeak(
                            text=text,
                            source_name="phoneinfoga",
                            source_url="",
                        ))
        except asyncio.TimeoutError:
            logger.debug("PhoneInfoga: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("PhoneInfoga error: %s", exc)

        return leaks
