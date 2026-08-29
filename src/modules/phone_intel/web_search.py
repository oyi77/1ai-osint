"""Public web-search source for phone numbers (DuckDuckGo HTML).

Finds public pages that mention a phone number — profile pages, forum posts,
business listings, leaked directories. Free, no API key. Ported from the
multi-API approach used by HackUnderway/SearchPhone, using 1ai-osint's
existing DDG HTML endpoint pattern.
"""

from __future__ import annotations

import html
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx

logger = logging.getLogger(__name__)

# DDG HTML result blocks: <a class="result__a" href="...">title</a> and the
# snippet in <a class="result__snippet">text</a> (or <div class="result__snippet">).
_RESULT_LINK_RE = re.compile(r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_SNIPPET_RE = re.compile(r'<(?:a|div)[^>]*class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div)>', re.S)
_TAG_RE = re.compile(r"<[^>]+>")


class PhoneWebSearch:
    """Search public web pages for a phone number via DuckDuckGo HTML."""

    ENDPOINTS = [
        ("duckduckgo_html", "https://html.duckduckgo.com/html/"),
        ("duckduckgo_lite", "https://lite.duckduckgo.com/lite/"),
    ]

    def __init__(
        self,
        max_results: int = 5,
        timeout: float = 15.0,
        request_delay: float = 2.0,
    ):
        self.max_results = max_results
        self.timeout = timeout
        self.request_delay = request_delay
        self._last_request = 0.0

    async def search(self, phone: str) -> list[dict[str, Any]]:
        """Return pages mentioning the phone: [{url, title, snippet}]."""
        query = f'"{phone}"'
        results: list[dict[str, Any]] = []
        for engine, endpoint in self.ENDPOINTS:
            if len(results) >= self.max_results:
                break
            try:
                found = await self._query(endpoint, query)
            except httpx.HTTPError as e:
                logger.debug("web search %s failed: %s", engine, e)
                continue
            results.extend(found)
            if self.request_delay:
                await asyncio_sleep(self.request_delay)
        # Dedupe by url, keep engine label.
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for r in results:
            if r["url"] in seen:
                continue
            seen.add(r["url"])
            r["engine"] = "duckduckgo"
            out.append(r)
            if len(out) >= self.max_results:
                break
        return out

    async def _query(self, endpoint: str, query: str) -> list[dict[str, Any]]:
        await self._throttle()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            resp = await client.get(endpoint, params={"q": query})
            resp.raise_for_status()
        links = _RESULT_LINK_RE.findall(resp.text)
        snippets = [_clean(s) for s in _SNIPPET_RE.findall(resp.text)]
        results: list[dict[str, Any]] = []
        for i, (href, title) in enumerate(links):
            url = _extract_real_url(href)
            if not url or "duckduckgo.com" in url or "lite.duckduckgo" in url:
                continue
            snippet = snippets[i] if i < len(snippets) else ""
            results.append({"url": url, "title": _clean(title), "snippet": snippet})
        return results

    async def _throttle(self) -> None:
        wait = self.request_delay - (time.monotonic() - self._last_request)
        if wait > 0:
            await asyncio_sleep(wait)
        self._last_request = time.monotonic()


async def asyncio_sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


def _clean(text: str) -> str:
    text = _TAG_RE.sub("", text)
    return html.unescape(text).strip()


def _extract_real_url(href: str) -> str:
    """DDG HTML links are redirects: //duckduckgo.com/l/?uddg=<url>&rut=..."""
    if "uddg=" in href:
        q = parse_qs(urlparse(href).query)
        if q.get("uddg"):
            return q["uddg"][0]
    return unquote(href) if href.startswith("http") else ""
