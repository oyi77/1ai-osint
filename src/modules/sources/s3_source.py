"""S3 bucket source adapter for exposed cloud storage scanning."""
from __future__ import annotations
import asyncio
import logging
import time
import httpx

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)


class S3Source:
    """Scan for exposed S3 buckets with crypto-related content."""

    BUCKET_PATTERNS = [
        "{target}-backup",
        "{target}-data",
        "{target}-config",
        "{target}-keys",
        "{target}-wallet",
        "{target}-crypto",
        "{target}-private",
        "{target}-secrets",
        "{target}-env",
        "{target}-credentials",
    ]

    def __init__(self, request_delay: float = 1.0, timeout: float = 10.0):
        self.request_delay = request_delay
        self.timeout = timeout
        self._last_request: float = 0.0

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """S3 requires a target — no bulk fetch."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Check for exposed S3 buckets related to a target."""
        leaks: list[RawLeak] = []
        # Clean target name
        target = address.split("@")[0].split(".")[0].lower().replace(" ", "-")

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for pattern in self.BUCKET_PATTERNS[:5]:
                bucket_name = pattern.format(target=target)
                try:
                    await self._rate_limit()
                    resp = await client.get(
                        f"https://{bucket_name}.s3.amazonaws.com/",
                        follow_redirects=False,
                    )
                    if resp.status_code == 200:
                        # Bucket exists and is publicly accessible
                        content = resp.text[:10000]
                        leaks.append(RawLeak(
                            text=f"Exposed S3 bucket: {bucket_name}\n{content}",
                            source_name="s3",
                            source_url=f"https://{bucket_name}.s3.amazonaws.com/",
                        ))
                except Exception:
                    pass  # Bucket doesn't exist or is private

        return leaks

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.request_delay:
            await asyncio.sleep(self.request_delay - elapsed)
        self._last_request = time.monotonic()
