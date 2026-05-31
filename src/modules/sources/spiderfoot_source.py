"""SpiderFoot source adapter for automated OSINT."""
from __future__ import annotations
import asyncio
import json
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class SpiderFootSource:
    """Use SpiderFoot for automated OSINT reconnaissance."""

    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """SpiderFoot requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Run SpiderFoot scan on a target."""
        leaks: list[RawLeak] = []
        sf_path = shutil.which("spiderfoot")
        if not sf_path:
            logger.debug("SpiderFoot: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                sf_path, "-s", address, "-m", "sfp_whois", "-o", "json",
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
                                source_name="spiderfoot",
                                source_url="",
                            ))
                except json.JSONDecodeError:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(RawLeak(
                            text=text,
                            source_name="spiderfoot",
                            source_url="",
                        ))
        except asyncio.TimeoutError:
            logger.debug("SpiderFoot: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("SpiderFoot error: %s", exc)

        return leaks
