"""Darknet Source — Tor-enabled onion intelligence crawler. Phase 5 Pillar 3.

Searches darknet indices (Ahmia) for mentions of target identifiers.
Requires Tor SOCKS5 proxy running at 127.0.0.1:9050.
Gracefully degrades when Tor is not available.
"""

from __future__ import annotations

import logging
import re
import socket
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, Field

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

_TOR_HOST = "127.0.0.1"
_TOR_PORT = 9050
_AHMIA_URL = "https://ahmia.fi/search/"
_DEFAULT_TIMEOUT = 30.0


class DarknetMention(BaseModel):
    """A mention of a target found on the darknet."""

    onion_url: str = ""
    title: str = ""
    snippet: str = ""
    category: str = "unknown"  # paste | forum | market | leak_db | unknown
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 0.5


class DarknetSource:
    """Query darknet indices (Ahmia.fi) via Tor SOCKS5 proxy for target mentions.

    Gracefully degrades when Tor is not reachable — returns an empty list
    and logs a warning instead of raising an exception.
    """

    source_id = "darknet"
    source_name = "Darknet Intelligence"

    # ------------------------------------------------------------------
    # Tor availability check
    # ------------------------------------------------------------------

    def _is_tor_available(self) -> bool:
        """Check if Tor SOCKS5 proxy is reachable."""
        try:
            with socket.create_connection((_TOR_HOST, _TOR_PORT), timeout=2.0):
                return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # URL classification
    # ------------------------------------------------------------------

    def _classify_url(self, url: str) -> str:
        """Classify a darknet URL into a category."""
        url_lower = url.lower()
        if any(k in url_lower for k in ("paste", "bin")):
            return "paste"
        if any(k in url_lower for k in ("forum", "chan", "board", "talk")):
            return "forum"
        if any(k in url_lower for k in ("market", "shop", "store", "vendor")):
            return "market"
        if any(k in url_lower for k in ("leak", "dump", "database", "db", "breach")):
            return "leak_db"
        return "unknown"

    # ------------------------------------------------------------------
    # Core search
    # ------------------------------------------------------------------

    async def search(self, query: str) -> list[DarknetMention]:
        """Search darknet indices via Ahmia for *query*.

        Returns an empty list (with a warning log) when Tor is unavailable
        or any network error occurs.
        """
        if not self._is_tor_available():
            logger.warning(
                "Tor SOCKS5 proxy not available at %s:%d — skipping darknet scan",
                _TOR_HOST,
                _TOR_PORT,
            )
            return []

        try:
            transport = httpx.AsyncHTTPTransport(
                proxy=f"socks5://{_TOR_HOST}:{_TOR_PORT}"
            )
            async with httpx.AsyncClient(
                transport=transport, timeout=_DEFAULT_TIMEOUT
            ) as client:
                resp = await client.get(_AHMIA_URL, params={"q": query})
                resp.raise_for_status()
                return self._parse_response(resp.text, query)
        except Exception as exc:
            logger.warning("Darknet search failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, html: str, query: str) -> list[DarknetMention]:
        """Parse Ahmia HTML search results into DarknetMention objects."""
        mentions: list[DarknetMention] = []

        # Extract onion URLs
        onion_pattern = re.compile(
            r"(https?://[a-z2-7]{16,56}\.onion[^\s\"<]*)", re.IGNORECASE
        )
        onion_urls = onion_pattern.findall(html)

        # Extract title / snippet pairs from Ahmia's result blocks
        result_blocks = re.findall(
            r"<h4>(.*?)</h4>.*?<p[^>]*>(.*?)</p>",
            html,
            re.DOTALL | re.IGNORECASE,
        )

        seen: set[str] = set()
        for i, (title, snippet) in enumerate(result_blocks[:10]):
            title_clean = re.sub(r"<[^>]+>", "", title).strip()
            snippet_clean = re.sub(r"<[^>]+>", "", snippet).strip()[:200]
            onion_url = onion_urls[i] if i < len(onion_urls) else ""

            if onion_url and onion_url in seen:
                continue
            seen.add(onion_url)

            if title_clean or snippet_clean:
                mentions.append(
                    DarknetMention(
                        onion_url=onion_url,
                        title=title_clean,
                        snippet=snippet_clean,
                        category=self._classify_url(onion_url or title_clean),
                        confidence=(
                            0.6 if query.lower() in snippet_clean.lower() else 0.4
                        ),
                    )
                )

        return mentions

    # ------------------------------------------------------------------
    # BaseLeakSource-compatible interface
    # ------------------------------------------------------------------

    async def fetch_raw_leaks(self) -> list[RawLeak]:
        """No bulk fetch — requires a query target. Returns empty list."""
        return []

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search darknet for *address* and return RawLeak records."""
        mentions = await self.search(address)
        leaks: list[RawLeak] = []
        for m in mentions:
            leaks.append(
                RawLeak(
                    text=(
                        f"[darknet/{m.category}] {m.title}\n"
                        f"URL: {m.onion_url}\n"
                        f"{m.snippet}"
                    ),
                    source_name=self.source_id,
                    source_url=m.onion_url,
                    metadata={
                        "category": m.category,
                        "confidence": m.confidence,
                        "title": m.title,
                        "snippet": m.snippet,
                        "extracted_at": m.extracted_at.isoformat(),
                    },
                )
            )
        return leaks
