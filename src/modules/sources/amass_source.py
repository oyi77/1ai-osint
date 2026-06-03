"""Amass source adapter for subdomain enumeration."""

from __future__ import annotations
import asyncio
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class AmassSource:
    """Use amass for subdomain enumeration and reconnaissance."""

    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Amass requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Enumerate subdomains for a domain using amass."""
        leaks: list[RawLeak] = []
        amass_path = shutil.which("amass")
        if not amass_path:
            logger.debug("Amass: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                amass_path,
                "enum",
                "-passive",
                "-d",
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
                            source_name="amass",
                            source_url="",
                        )
                    )
        except asyncio.TimeoutError:
            logger.debug("Amass: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("Amass error: %s", exc)

        return leaks
