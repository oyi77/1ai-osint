"""data.go.id Intelligence — Indonesian government open data search.

Queries Portal Satu Data Indonesia (data.go.id, managed by Sekretariat SDI /
Kementerian PPN/Bappenas) for public government datasets matching a keyword.

The portal is a Next.js app; dataset listings are server-rendered and the
keyword search results are embedded in the page's React flight data. This
adapter fetches the search page and extracts dataset titles/organizations
with a tolerant regex (no fragile JS execution).

Legal basis: government open data published under Satu Data Indonesia —
the strongest basis under UU PDP (public disclosure by law).
"""

from __future__ import annotations

import html
import logging
import re

import httpx

logger = logging.getLogger(__name__)

SEARCH_URL = "https://data.go.id/dataset"
USER_AGENT = "1ai-osint/1.0 (+government open data research)"

# Flight-data title extraction: JSON string keys inside the RSC payload.
_TITLE_RE = re.compile(r'\\"title\\":\\"((?:[^\\"]|\\\\.){3,120})\\"')
_ORG_RE = re.compile(r'\\"(?:nama_organisasi|organization|instansi)\\":\\"((?:[^\\"]|\\\\.){3,120})\\"')


def _unescape(value: str) -> str:
    """Undo the double-encoding used in Next.js flight data strings."""
    return html.unescape(value.replace('\\"', '"').replace("\\\\", "\\"))


class DataGoIdIntel:
    """Search data.go.id for public datasets by keyword."""

    async def search_datasets(self, keyword: str, limit: int = 8) -> list[dict]:
        """Return up to ``limit`` dataset metadata dicts.

        Each dict: {"title": str, "organization": str}.
        """
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                resp = await client.get(SEARCH_URL, params={"keyword": keyword})
                if resp.status_code != 200:
                    logger.debug("data.go.id search -> HTTP %s", resp.status_code)
                    return []
                text = resp.text
        except Exception as e:
            logger.debug("data.go.id search failed for %q: %s", keyword, e)
            return []

        titles: list[str] = []
        for m in _TITLE_RE.finditer(text):
            title = _unescape(m.group(1)).strip()
            if title and title not in titles:
                titles.append(title)
            if len(titles) >= limit * 2:
                break

        orgs = [_unescape(m.group(1)).strip() for m in _ORG_RE.finditer(text)]

        # Filter out UI chrome strings ("kategori", org names, etc.) that
        # happen to live in title-shaped JSON — keep plausible dataset names.
        results: list[dict] = []
        stopwords = {"kategori", "Semua Data", "Dataset", "Homepage", "Contact"}
        for title in titles:
            if title in stopwords or len(title) < 12:
                continue
            results.append(
                {
                    "title": title,
                    "organization": orgs[0] if orgs else "",
                }
            )
            if len(results) >= limit:
                break
        return results
