import requests
from src.vendor.chiasmodon.base import OSINTTool


class PastebinTool(OSINTTool):
    """Pastebin search via scraping (no official API for search)."""

    name = "pastebin"
    SEARCH_URL = "https://pastebin.com/search"

    def search(self, query, **kwargs):
        try:
            from bs4 import BeautifulSoup

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; 1ai-osint/0.1)",
            }
            resp = requests.get(
                self.SEARCH_URL,
                params={"q": query},
                headers=headers,
                timeout=30,
            )
            if resp.status_code != 200:
                return {"status": "error", "tool": self.name, "error": f"HTTP {resp.status_code}"}
            # Parse paste links from search results
            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for link in soup.select("a[href^='/']"):
                href = link.get("href", "")
                text = link.get_text(strip=True)
                if href.startswith("/") and len(href) > 1 and text:
                    results.append({
                        "url": f"https://pastebin.com{href}",
                        "title": text,
                    })
            return {
                "status": "ok",
                "tool": self.name,
                "query": query,
                "result": results[:kwargs.get("limit", 50)],
            }
        except ImportError:
            return {"status": "error", "tool": self.name, "error": "beautifulsoup4 not installed"}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}

    def scan(self, query, **kwargs):
        return {"status": "error", "tool": self.name, "error": "Scan not supported"}

    def analyze(self, data, **kwargs):
        return {"note": "Not implemented"}

    def learn(self, feedback, **kwargs):
        pass
