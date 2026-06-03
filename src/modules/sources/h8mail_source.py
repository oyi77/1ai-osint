"""h8mail source adapter for email breach lookup."""

from __future__ import annotations
import asyncio
import json
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class H8mailSource:
    """Use h8mail for email breach and credential lookup."""

    def __init__(self, timeout: float = 120.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """h8mail requires an email target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search for breached credentials associated with an email."""
        leaks: list[RawLeak] = []
        if "@" not in address:
            return leaks

        h8mail_path = shutil.which("h8mail")
        if not h8mail_path:
            logger.debug("h8mail: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                h8mail_path,
                "-t",
                address,
                "--json",
                "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    if isinstance(results, list):
                        for entry in results:
                            leaks.append(
                                RawLeak(
                                    text=json.dumps(entry),
                                    source_name="h8mail",
                                    source_url="",
                                )
                            )
                    elif isinstance(results, dict):
                        leaks.append(
                            RawLeak(
                                text=json.dumps(results),
                                source_name="h8mail",
                                source_url="",
                            )
                        )
                except json.JSONDecodeError:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(
                            RawLeak(
                                text=text,
                                source_name="h8mail",
                                source_url="",
                            )
                        )
        except asyncio.TimeoutError:
            logger.debug("h8mail: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("h8mail error: %s", exc)

        return leaks
