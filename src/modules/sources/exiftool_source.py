"""ExifTool source adapter for metadata extraction."""

from __future__ import annotations
import asyncio
import json
import logging
import shutil

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class ExiftoolSource:
    """Use ExifTool to extract metadata from files and URLs."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """ExifTool requires a file target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Extract metadata from a file path or URL."""
        leaks: list[RawLeak] = []
        exiftool_path = shutil.which("exiftool")
        if not exiftool_path:
            logger.debug("ExifTool: binary not found, skipping")
            return leaks

        try:
            proc = await asyncio.create_subprocess_exec(
                exiftool_path,
                "-json",
                "-G",
                address,
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
                                    text=json.dumps(entry, indent=2),
                                    source_name="exiftool",
                                    source_url=address,
                                )
                            )
                except json.JSONDecodeError:
                    text = stdout.decode()
                    if text.strip():
                        leaks.append(
                            RawLeak(
                                text=text,
                                source_name="exiftool",
                                source_url=address,
                            )
                        )
        except asyncio.TimeoutError:
            logger.debug("ExifTool: timeout for '%s'", address)
        except Exception as exc:
            logger.debug("ExifTool error: %s", exc)

        return leaks
