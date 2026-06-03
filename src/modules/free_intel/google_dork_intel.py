"""Google Dork Intelligence via DuckDuckGo — extracts PII from search snippets."""

import re
import logging
import asyncio
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class DorkResult(BaseModel):
    query: str = ""
    urls: list[str] = Field(default_factory=list)
    snippets: list[str] = Field(default_factory=list)
    extracted_emails: list[str] = Field(default_factory=list)
    extracted_phones: list[str] = Field(default_factory=list)
    linkedin_urls: list[str] = Field(default_factory=list)
    pdf_urls: list[str] = Field(default_factory=list)


class GoogleDorkIntel:
    """Uses DuckDuckGo HTML to run targeted OSINT dorks."""

    ENDPOINTS = [
        "https://html.duckduckgo.com/html/",
        "https://lite.duckduckgo.com/lite/",
    ]

    DORK_TEMPLATES = [
        '"{name}" site:linkedin.com',
        '"{name}" site:facebook.com',
        '"{name}" email OR @gmail.com OR @yahoo.com',
        '"{name}" phone OR "nomor" OR "HP" OR "whatsapp"',
        '"{name}" CV OR resume filetype:pdf',
        '"{name}" site:scholar.google.com',
        '"{name}" site:researchgate.net',
        '"{name}" site:techinasia.com OR site:glints.com',
        '"{name}" site:kaggle.com OR site:medium.com',
    ]

    async def search(self, name: str) -> DorkResult:
        """Run all dorks for a name and extract intelligence."""
        result = DorkResult(query=name)
        all_snippets = []

        async with httpx.AsyncClient(
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        ) as client:
            for template in self.DORK_TEMPLATES:
                query = template.format(name=name)
                try:
                    snippet_text = await self._run_dork(client, query)
                    if snippet_text:
                        all_snippets.append(snippet_text)
                    await asyncio.sleep(1.5)  # Rate limit
                except Exception as e:
                    logger.debug("Dork failed for %s: %s", query, e)

        combined = "\n".join(all_snippets)
        result.snippets = all_snippets

        # Extract emails
        result.extracted_emails = list(
            set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", combined))
        )

        # Extract phone numbers (Indonesian format: 08xx, +62xx, international)
        phones = re.findall(r"(?:\+62|62|0)\d{9,12}", combined)
        phones += re.findall(r"\+?\d{10,14}", combined)
        result.extracted_phones = list(set(phones))

        # Extract LinkedIn URLs
        result.linkedin_urls = list(
            set(
                re.findall(
                    r"https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_-]+", combined
                )
            )
        )

        # Extract PDF URLs (CVs/resumes)
        result.pdf_urls = list(set(re.findall(r'https?://[^\s"<>]+\.pdf', combined)))

        # Extract all URLs
        result.urls = list(set(re.findall(r'https?://[^\s"<>]+', combined)))[:20]

        # Phase 9: Fetch raw text from top high-value links (LinkedIn previews, PDFs)
        high_value = [
            u
            for u in result.urls
            if "linkedin.com/in" in u or "glints" in u or u.endswith(".pdf")
        ]
        if not high_value:
            high_value = result.urls[:2]  # Fallback to top 2 general links

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "1ai-osint-scraper/1.0"},
        ) as fetch_client:
            for url in high_value[:3]:
                try:
                    resp = await fetch_client.get(url)
                    if resp.status_code == 200:
                        # Strip HTML and keep text
                        import html

                        text = re.sub(
                            r"<script.*?>.*?</script>",
                            "",
                            resp.text,
                            flags=re.DOTALL | re.IGNORECASE,
                        )
                        text = re.sub(
                            r"<style.*?>.*?</style>",
                            "",
                            text,
                            flags=re.DOTALL | re.IGNORECASE,
                        )
                        text = re.sub(r"<[^>]+>", " ", text)
                        clean_text = " ".join(html.unescape(text).split())
                        # Add a big chunk of text as a snippet
                        if clean_text:
                            result.snippets.append(
                                f"Content from {url}:\n{clean_text[:1500]}"
                            )
                except Exception:
                    pass

        return result

    async def _run_dork(self, client: httpx.AsyncClient, query: str) -> str:
        """Execute a single dork query via DuckDuckGo."""
        for endpoint in self.ENDPOINTS:
            try:
                resp = await client.post(endpoint, data={"q": query})
                if resp.status_code == 200:
                    # Extract snippets from result HTML
                    text = resp.text
                    # Remove HTML tags but keep text content
                    snippets = re.findall(
                        r'class="result__snippet"[^>]*>(.*?)</a', text, re.DOTALL
                    )
                    if not snippets:
                        snippets = re.findall(
                            r'<td[^>]*class="result-snippet"[^>]*>(.*?)</td>',
                            text,
                            re.DOTALL,
                        )
                    if not snippets:
                        # Fallback: extract all text between <a> tags that look like results
                        snippets = re.findall(
                            r'class="[^"]*snippet[^"]*"[^>]*>(.*?)</', text, re.DOTALL
                        )
                    clean = " ".join(
                        re.sub(r"<[^>]+>", " ", s).strip() for s in snippets
                    )

                    # Also extract result URLs
                    urls = re.findall(r'href="(https?://[^"]+)"', text)
                    urls = [
                        u for u in urls if "duckduckgo" not in u and "lite" not in u
                    ]

                    return clean + " " + " ".join(urls)
            except Exception:
                continue
        return ""
