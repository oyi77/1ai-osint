"""Recon-ng source adapter for OSINT reconnaissance."""
from __future__ import annotations
import asyncio
import json
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class ReconNgSource:
    """Use recon-ng for automated OSINT reconnaissance."""

    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """Recon-ng requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Run recon-ng scan on a target."""
        leaks: list[RawLeak] = []
        reconng_path = shutil.which("recon-ng")
        if not reconng_path:
            logger.debug("Recon-ng: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                reconng_path, "-r", address, "-j", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    if isinstance(results, list):
                        for entry in results:
                            leaks.append(RawLeak(
                                text=json.dumps(entry),
                                source_name="recon_ng",
                                source_url="",
                            ))
                except json.JSONDecodeError:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(RawLeak(
                            text=text,
                            source_name="recon_ng",
                            source_url="",
                        ))
        except asyncio.TimeoutError:
            logger.debug("Recon-ng: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("Recon-ng error: %s", exc)

        return leaks
