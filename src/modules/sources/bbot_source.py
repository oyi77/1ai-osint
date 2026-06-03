"""BBOT source adapter for recursive OSINT scanning."""

from __future__ import annotations
import asyncio
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class BbotSource:
    """Use BBOT for recursive OSINT scanning (subdomains, emails, web content)."""

    PRESETS = [
        "subdomain-enum",
        "email-enum",
        "web-basic",
    ]

    def __init__(self, timeout: float = 600.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """BBOT requires a domain target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Run BBOT scan on a target (domain, IP, URL, email)."""
        leaks: list[RawLeak] = []
        bbot_path = shutil.which("bbot")
        if not bbot_path:
            logger.debug("BBOT: binary not found, skipping")
            return leaks

        for preset in self.PRESETS:
            try:
                proc = await asyncio.create_subprocess_exec(
                    bbot_path,
                    "-t",
                    address,
                    "-p",
                    preset,
                    "-y",
                    "-q",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=min(self.timeout, 120)
                )
                if stdout:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(
                            RawLeak(
                                text=text[:100000],
                                source_name=f"bbot_{preset}",
                                source_url="",
                            )
                        )
            except asyncio.TimeoutError:
                logger.debug("BBOT %s: timeout for '%s'", preset, address)
            except Exception as exc:
                logger.debug("BBOT %s error: %s", preset, exc)

        return leaks
