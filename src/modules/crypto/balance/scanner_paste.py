"""Pastebin and paste site scanner for mnemonic leaks."""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

from src.modules.crypto.balance._leak_shared import (
    LeakFinding,
    MnemonicPatternDetector,
    verify_and_alert,
)
from src.modules.crypto.balance.chains import ChainConfig
from src.modules.crypto.balance.hit_logger import HitLogger

logger = logging.getLogger(__name__)


class PasteSiteScanner:
    """Pastebin and paste site scanner for mnemonic leaks."""

    PASTE_SOURCES = [
        "https://pastebin.com/archive",
        "https://paste.ee/archive",
    ]

    def __init__(self, hit_logger: Optional[HitLogger] = None):
        self.hit_logger = hit_logger

    async def scan(self, max_pastes: int = 50) -> list[LeakFinding]:
        """Scan recent pastes for mnemonic patterns.

        Args:
            max_pastes: Maximum number of pastes to check.

        Returns:
            List of LeakFinding objects with candidates.
        """
        findings = []

        async with httpx.AsyncClient(timeout=30) as client:
            for source in self.PASTE_SOURCES:
                try:
                    paste_urls = await self._get_paste_urls(client, source, max_pastes)
                    for url in paste_urls:
                        finding = await self._scan_paste(client, url)
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    logger.error("Paste scan error (%s): %s", source, e)

        return findings

    async def _get_paste_urls(
        self, client: httpx.AsyncClient, archive_url: str, limit: int
    ) -> list[str]:
        """Extract paste URLs from an archive page."""
        try:
            resp = await client.get(archive_url)
            resp.raise_for_status()
            # Extract paste links (simplified — would need site-specific parsing)
            urls = re.findall(r'https?://pastebin\.com/[a-zA-Z0-9]+', resp.text)
            return list(dict.fromkeys(urls))[:limit]  # deduplicate, limit
        except Exception:
            return []

    async def _scan_paste(
        self, client: httpx.AsyncClient, paste_url: str
    ) -> Optional[LeakFinding]:
        """Fetch a paste and scan for mnemonics and private keys."""
        try:
            # Pastebin raw URL
            raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
            resp = await client.get(raw_url)
            resp.raise_for_status()
            text = resp.text

            # Pass 1: mnemonic detection
            candidates = MnemonicPatternDetector.find_mnemonics(text)
            if candidates:
                return LeakFinding(
                    source="pastebin",
                    source_url=paste_url,
                    mnemonic_candidate=candidates[0],
                    is_valid=True,
                )

            # Pass 2: private key detection
            from src.modules.crypto.privatekey.scanner import detect_key_format
            keys = detect_key_format(text)
            if keys:
                for k in keys:
                    if k["format"] in ("hex_32byte", "hex_0x", "wif", "base58"):
                        return LeakFinding(
                            source="pastebin",
                            source_url=paste_url,
                            mnemonic_candidate=k["match"],
                            is_valid=False,
                            source_type="private_key",
                        )
        except Exception as e:
            logger.debug("Failed to scan paste %s: %s", paste_url, e)

        return None

    async def verify_and_alert(
        self,
        mnemonic_candidate: str,
        chains: Optional[list[ChainConfig]] = None,
        count: int = 6,
    ) -> Optional[LeakFinding]:
        """Validate and check a paste-sourced mnemonic candidate.

        Delegates to the standalone verify_and_alert function.

        Args:
            mnemonic_candidate: Potential mnemonic phrase to verify.
            chains: Chains to check. Defaults to all.
            count: Number of address indices to derive per chain (default 6 for leak-sourced).
        """
        return await verify_and_alert(
            mnemonic_candidate,
            chains=chains,
            hit_logger=self.hit_logger,
            count=count,
            source="pastebin",
        )