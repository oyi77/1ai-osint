"""httpx source adapter for HTTP probing."""

from __future__ import annotations

import asyncio
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class HttpxSource:
    """Use httpx for HTTP probing and technology detection."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """httpx requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Probe HTTP services on a target using httpx."""
        leaks: list[RawLeak] = []
        httpx_path = shutil.which("httpx")
        if not httpx_path:
            logger.debug("httpx: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                httpx_path,
                "-u",
                address,
                "-silent",
                "-json",
                "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if stdout:
                try:
                    import json

                    results = json.loads(stdout.decode())
                    if isinstance(results, list):
                        for entry in results:
                            leaks.append(
                                RawLeak(
                                    text=json.dumps(entry),
                                    source_name="httpx",
                                    source_url=address,
                                )
                            )
                except Exception:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(
                            RawLeak(
                                text=text,
                                source_name="httpx",
                                source_url=address,
                            )
                        )
        except asyncio.TimeoutError:
            logger.debug("httpx: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("httpx error: %s", exc)

        return leaks
