"""Nmap source adapter for port scanning."""

from __future__ import annotations

import asyncio
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class NmapSource:
    """Use nmap for port scanning and service detection."""

    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Nmap requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Scan ports on a target using nmap."""
        leaks: list[RawLeak] = []
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            logger.debug("Nmap: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                nmap_path,
                "-sV",
                "-oX",
                "-",
                address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if stdout:
                text = stdout.decode()
                if text.strip():
                    leaks.append(
                        RawLeak(
                            text=text,
                            source_name="nmap",
                            source_url="",
                        )
                    )
        except asyncio.TimeoutError:
            logger.debug("Nmap: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("Nmap error: %s", exc)

        return leaks
