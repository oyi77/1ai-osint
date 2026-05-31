"""Maigret source adapter for username enumeration."""
from __future__ import annotations
import asyncio
import json
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class MaigretSource:
    """Use maigret to find usernames across 2000+ sites."""

    def __init__(self, timeout: float = 180.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Maigret requires a username target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search for a username across 2000+ sites using maigret."""
        leaks: list[RawLeak] = []
        maigret_path = shutil.which("maigret")
        if not maigret_path:
            logger.debug("Maigret: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                maigret_path, address, "--json", "simple", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    for site, data in results.items():
                        if data.get("status") == "Claimed":
                            url = data.get("url", "")
                            leaks.append(RawLeak(
                                text=f"Username '{address}' found on {site}: {url}",
                                source_name="maigret",
                                source_url=url,
                            ))
                except json.JSONDecodeError:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(RawLeak(
                            text=text,
                            source_name="maigret",
                            source_url="",
                        ))
        except asyncio.TimeoutError:
            logger.debug("Maigret: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("Maigret error: %s", exc)

        return leaks
