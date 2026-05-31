"""Sherlock source adapter for username enumeration."""
from __future__ import annotations
import asyncio
import json
import logging
import shutil


from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class SherlockSource:
    """Use sherlock-project to find usernames across social networks."""

    def __init__(self, timeout: float = 120.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Sherlock requires a username target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search for a username across social networks using sherlock."""
        leaks: list[RawLeak] = []
        sherlock_path = shutil.which("sherlock")
        if not sherlock_path:
            logger.debug("Sherlock: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                sherlock_path, address, "--json", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    for site, data in results.items():
                        if data.get("status") == "Claimed":
                            leaks.append(RawLeak(
                                text=f"Username '{address}' found on {site}: {data.get('url', '')}",
                                source_name="sherlock",
                                source_url=data.get("url", ""),
                            ))
                except json.JSONDecodeError:
                    # sherlock may output non-JSON
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(RawLeak(
                            text=text,
                            source_name="sherlock",
                            source_url="",
                        ))
        except asyncio.TimeoutError:
            logger.debug("Sherlock: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("Sherlock error: %s", exc)

        return leaks
