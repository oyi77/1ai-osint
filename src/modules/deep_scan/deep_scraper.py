"""Production-grade deep scraper with retry, UA rotation, caching, and rate limiting.

Features:
- Exponential backoff retry (3 attempts, delay doubling)
- Intelligent content extraction (article body, metadata, structured data)
- User-Agent rotation from a pool of 10+ realistic UAs
- Request timing randomization to avoid fingerprinting
- Content type detection (HTML, JSON, PDF, image)
- Max depth for recursive scraping
- Rate limiting per domain via RateLimiter
- Response caching via Cache
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from src.core.cache import Cache
from src.core.rate_limiter import RateLimiter
from src.core.ssrf_guard import validate_scan_target

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class DeepScraperResult:
    """Normalised result from a scrape operation."""

    url: str
    title: str = ""
    text_content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"  # ok, error, skipped
    error: str | None = None
    elapsed_ms: float = 0.0


# ---------------------------------------------------------------------------
# User-Agent pool
# ---------------------------------------------------------------------------

USER_AGENTS: list[str] = [
    # Chrome 120+ on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox 121 on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari 17 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# ---------------------------------------------------------------------------
# Content type detection
# ---------------------------------------------------------------------------

TEXT_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
}

BINARY_CONTENT_TYPES = {
    "application/pdf",
    "image/",
    "application/zip",
    "application/gzip",
    "application/octet-stream",
}

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class DeepScraperEngine:
    """Production-grade web scraper with anti-detection and resilience features.

    The engine wraps **httpx** for direct HTTP requests, falling back to
    **CloakScraper** for JavaScript-rendered pages when needed.  It applies
    exponential-backoff retries, per-domain rate limiting, response caching,
    and realistic User-Agent rotation.
    """

    def __init__(
        self,
        max_retries: int = 3,
        request_delay_range: tuple[float, float] = (0.5, 2.0),
        max_depth: int = 2,
        cache_ttl: int = 3600,
        cache_dir: str | None = None,
        rate_limiter: RateLimiter | None = None,
        cache: Cache | None = None,
    ) -> None:
        """Args:
        max_retries: Number of retries on failure (default 3).
        request_delay_range: (min, max) seconds to randomly delay
            between requests.
        max_depth: Maximum depth for recursive scraping
            (default 2, 1 = no recursion).
        cache_ttl: Cache TTL in seconds (default 3600).
        cache_dir: Optional custom cache directory path.
        rate_limiter: Shared or standalone RateLimiter instance.
        cache: Shared or standalone Cache instance.

        """
        self.max_retries = max_retries
        self.delay_range = request_delay_range
        self.max_depth = max_depth
        self._rate_limiter = rate_limiter or RateLimiter(requests_per_minute=30, burst=5)
        if cache is not None:
            self._cache = cache
        else:
            self._cache = Cache(
                cache_dir=cache_dir if cache_dir is None else __import__("pathlib").Path(cache_dir),
                default_ttl=cache_ttl,
            )

        # Semi-persistent HTTP client for connection reuse
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        """Return a shared httpx AsyncClient, creating one if needed."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=True,
                headers={"Accept-Language": "en-US,en;q=0.9"},
            )
        return self._client

    def _random_ua(self) -> str:
        """Pick a random User-Agent from the pool."""
        return random.choice(USER_AGENTS)

    async def _random_delay(self) -> None:
        """Sleep a random amount within the configured delay range to avoid fingerprinting."""
        delay = random.uniform(*self.delay_range)
        await asyncio.sleep(delay)

    def _detect_content_type(self, content_type: str) -> str:
        """Classify the content type of a response.

        Returns one of: 'html', 'json', 'pdf', 'image', 'binary', 'text'.
        """
        ct = (content_type or "").lower()
        if "text/html" in ct or "xhtml" in ct:
            return "html"
        if "application/json" in ct or "+json" in ct:
            return "json"
        if "application/pdf" in ct:
            return "pdf"
        if ct.startswith("image/"):
            return "image"
        if ct.startswith("text/"):
            return "text"
        return "binary"

    # ------------------------------------------------------------------
    # Content extraction
    # ------------------------------------------------------------------

    def _extract_html_content(self, html: str) -> dict[str, Any]:
        """Extract title, text content, and metadata from HTML.

        Uses basic tag-based extraction (no external parser dependency)
        with a lightweight fallback that works well for most pages.
        """
        result: dict[str, Any] = {
            "title": "",
            "text_content": "",
            "metadata": {},
        }

        # -- Title --
        import re

        m = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", html, re.IGNORECASE | re.DOTALL)
        if m:
            result["title"] = self._clean_text(m.group(1))

        # -- Meta tags --
        for tag in ("description", "keywords", "author"):
            m = re.search(
                rf'<meta[^>]+(?:name|property)=["\']{tag}["\'][^>]*' rf'content=["\'](.*?)["\'][^>]*/?>',
                html,
                re.IGNORECASE,
            )
            if not m:
                m = re.search(
                    rf'<meta[^>]+content=["\'](.*?)["\'][^>]*' rf'(?:name|property)=["\']{tag}["\'][^>]*/?>',
                    html,
                    re.IGNORECASE,
                )
            if m:
                result["metadata"][tag] = self._clean_text(m.group(1))

        # -- Open Graph tags --
        for og_prop in ("title", "description", "image", "url", "site_name"):
            m = re.search(
                rf'<meta[^>]+property=["\']og:{og_prop}["\'][^>]*' rf'content=["\'](.*?)["\'][^>]*/?>',
                html,
                re.IGNORECASE,
            )
            if m:
                result["metadata"][f"og:{og_prop}"] = self._clean_text(m.group(1))

        # -- Canonical URL --
        m = re.search(
            r'<link[^>]+rel=["\']canonical["\'][^>]*href=["\'](.*?)["\'][^>]*/?>',
            html,
            re.IGNORECASE,
        )
        if m:
            result["metadata"]["canonical"] = m.group(1).strip()

        # -- JSON-LD structured data --
        json_ld_blocks: list[str] = re.findall(
            r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            html,
            re.IGNORECASE | re.DOTALL,
        )
        import json

        for block in json_ld_blocks:
            try:
                data = json.loads(block.strip())
                result["metadata"]["json_ld"] = data
                # Promote common fields to top-level metadata
                if isinstance(data, dict):
                    for key in ("headline", "name", "description", "author"):
                        if key in data:
                            result["metadata"].setdefault("structured_title", str(data[key]))
            except json.JSONDecodeError:
                pass

        # -- Article text (extract <p>, <h1>-<h6>, <li> text) --
        text_parts: list[str] = []
        for tag in ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "blockquote"):
            for match in re.finditer(rf"<{tag}[^>]*>(.*?)</{tag}>", html, re.IGNORECASE | re.DOTALL):
                text = self._strip_tags(match.group(1))
                if text:
                    text_parts.append(text)

        # -- Also grab body text outside those tags --
        body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.IGNORECASE | re.DOTALL)
        if body_match:
            body_text = self._strip_tags(body_match.group(1))
            # Only use if structured extraction was weak
            if len(" ".join(text_parts)) < 200:
                text_parts.append(body_text)

        result["text_content"] = " ".join(text_parts)

        return result

    @staticmethod
    def _clean_text(text: str) -> str:
        """Normalise whitespace and strip HTML entities."""
        import html as html_mod
        import re

        text = html_mod.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def _strip_tags(html_fragment: str) -> str:
        """Remove HTML tags from a fragment, preserving whitespace."""
        import re

        text = re.sub(r"<[^>]+>", " ", html_fragment)
        return DeepScraperEngine._clean_text(text)

    # ------------------------------------------------------------------
    # Core scrape
    # ------------------------------------------------------------------

    async def scrape(
        self,
        url: str,
        depth: int = 0,
        _visited: set[str] | None = None,
    ) -> DeepScraperResult:
        """Scrape a URL with full retry, caching, and rate-limiting.

        Args:
            url: The URL to scrape.
            depth: Current recursion depth (internal).
            _visited: Set of visited URLs (internal, for cycle prevention).

        Returns:
            A DeepScraperResult with extracted content.

        """
        start = time.perf_counter()

        if _visited is None:
            _visited = set()

        # Reject private/internal targets (SSRF protection) before any request.
        if not validate_scan_target(url):
            return DeepScraperResult(url=url, status="skipped", error="Blocked by SSRF guard")

        if url in _visited:
            return DeepScraperResult(url=url, status="skipped", error="Already visited")
        _visited.add(url)

        # --- Check cache ---
        cache_key = f"scrape:{url}"
        cached: dict[str, Any] | None = self._cache.get(cache_key)
        if cached is not None:
            elapsed = (time.perf_counter() - start) * 1000
            return DeepScraperResult(
                url=cached.get("url", url),
                title=cached.get("title", ""),
                text_content=cached.get("text_content", ""),
                metadata=cached.get("metadata", {}),
                status="ok",
                elapsed_ms=elapsed,
            )

        # --- Rate limit ---
        from urllib.parse import urlparse

        domain = urlparse(url).netloc
        wait = await self._rate_limiter.acquire_async(key=f"scrape:{domain}")
        if wait > 0:
            logger.debug("Rate-limited %s for %.2fs", domain, wait)

        # --- Retry loop ---
        last_error: str | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                client = await self._get_client()
                ua = self._random_ua()

                response = await client.get(
                    url,
                    headers={"User-Agent": ua},
                )
                response.raise_for_status()

                content_type = response.headers.get("content-type", "")
                ctype = self._detect_content_type(content_type)

                # --- Extract content ---
                extracted: dict[str, Any] = {
                    "title": "",
                    "text_content": "",
                    "metadata": {"content_type": ctype},
                }

                if ctype == "html":
                    extracted = self._extract_html_content(response.text)
                    extracted["metadata"]["content_type"] = "html"
                elif ctype == "json":
                    extracted["text_content"] = response.text
                    extracted["metadata"]["content_type"] = "json"
                elif ctype == "pdf":
                    extracted["metadata"]["content_type"] = "pdf"
                    extracted["text_content"] = f"[PDF document: {len(response.content)} bytes]"
                elif ctype == "image":
                    extracted["metadata"]["content_type"] = "image"
                    extracted["text_content"] = f"[Image: {len(response.content)} bytes, {content_type}]"
                else:
                    extracted["text_content"] = response.text[:5000]
                    extracted["metadata"]["content_type"] = ctype

                # --- Store in cache ---
                cache_data: dict[str, Any] = {
                    "url": url,
                    "title": extracted.get("title", ""),
                    "text_content": extracted.get("text_content", ""),
                    "metadata": extracted.get("metadata", {}),
                }
                self._cache.set(cache_key, cache_data)

                # --- Recursive scraping ---
                if ctype == "html" and depth < self.max_depth:
                    extracted["metadata"]["linked_urls"] = await self._extract_links(
                        response.text, url, depth + 1, _visited
                    )

                elapsed = (time.perf_counter() - start) * 1000
                return DeepScraperResult(
                    url=url,
                    title=extracted.get("title", ""),
                    text_content=extracted.get("text_content", ""),
                    metadata=extracted.get("metadata", {}),
                    status="ok",
                    elapsed_ms=elapsed,
                )

            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}"
                logger.debug(
                    "Attempt %d/%d for %s failed: %s",
                    attempt,
                    self.max_retries,
                    url,
                    last_error,
                )
                if attempt < self.max_retries:
                    delay = 2 ** (attempt - 1)  # exponential backoff: 1, 2, 4
                    delay += random.uniform(0, 0.5)  # jitter
                    logger.debug("Backoff %.2fs before retry", delay)
                    await asyncio.sleep(delay)

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_error = str(e)
                logger.debug(
                    "Attempt %d/%d for %s failed: %s",
                    attempt,
                    self.max_retries,
                    url,
                    last_error,
                )
                if attempt < self.max_retries:
                    delay = 2 ** (attempt - 1)
                    delay += random.uniform(0, 0.5)
                    await asyncio.sleep(delay)

            except Exception as e:
                last_error = str(e)
                logger.debug(
                    "Attempt %d/%d for %s failed unexpectedly: %s",
                    attempt,
                    self.max_retries,
                    url,
                    last_error,
                )
                break  # do not retry unknown errors

        elapsed = (time.perf_counter() - start) * 1000
        return DeepScraperResult(
            url=url,
            status="error",
            error=last_error or "Unknown error",
            elapsed_ms=elapsed,
        )

    async def _extract_links(
        self,
        html: str,
        base_url: str,
        depth: int,
        visited: set[str],
    ) -> list[dict[str, str]]:
        """Extract same-domain links for recursive scraping.

        Returns a list of {url, title} dicts from scraping linked pages.
        """
        import re
        from urllib.parse import urljoin, urlparse

        base_domain = urlparse(base_url).netloc
        links_found: set[str] = set()

        for m in re.finditer(
            r'<a[^>]+href=["\'](.*?)["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            href = m.group(1).strip()
            # Resolve relative URLs
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            # Only follow same-domain http(s) links
            if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
                links_found.add(full)

        # Scrape discovered links up to depth
        results: list[dict[str, str]] = []
        for link in list(links_found)[:5]:  # max 5 per page
            if link not in visited:
                child = await self.scrape(link, depth=depth, _visited=visited)
                if child.status == "ok" and child.title:
                    results.append({"url": link, "title": child.title})
                await self._random_delay()

        return results

    # ------------------------------------------------------------------
    # Backward-compatible API
    # ------------------------------------------------------------------

    async def scrape_profile(self, url: str) -> dict[str, Any]:
        """Scrape a profile/URL, returning a plain dict (backward-compatible).

        This method is kept for backward compatibility with existing callers.
        New code should use :meth:`scrape` which returns a typed
        ``DeepScraperResult``.

        Args:
            url: The profile URL to scrape.

        Returns:
            A dict with keys ``url``, ``title``, ``text_content``,
            ``profile_picture_url`` (empty string if not found).

        """
        result = await self.scrape(url)

        # Try to locate a profile/avatar picture from Open Graph metadata
        pfp_url = ""
        if result.metadata:
            pfp_url = result.metadata.get("og:image", "")
            if not pfp_url:
                pfp_url = result.metadata.get("image", "")

        return {
            "url": result.url,
            "title": result.title,
            "text_content": result.text_content,
            "profile_picture_url": pfp_url,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release the HTTP client and flush rate limiter state."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._rate_limiter.close()

    async def __aenter__(self) -> DeepScraperEngine:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
