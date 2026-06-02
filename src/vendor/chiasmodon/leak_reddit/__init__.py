import requests
from src.vendor.chiasmodon.base import OSINTTool


class RedditLeakTool(OSINTTool):
    """Reddit search for leaked credentials via old.reddit.com JSON API."""

    name = "redditleak"
    SEARCH_URL = "https://www.reddit.com/search.json"

    def search(self, query, **kwargs):
        try:
            headers = {
                "User-Agent": "1ai-osint/0.1 (OSINT research tool)",
            }
            resp = requests.get(
                self.SEARCH_URL,
                params={
                    "q": query,
                    "sort": "new",
                    "limit": kwargs.get("limit", 25),
                    "t": kwargs.get("time_filter", "month"),
                },
                headers=headers,
                timeout=30,
            )
            if resp.status_code != 200:
                return {"status": "error", "tool": self.name, "error": f"HTTP {resp.status_code}"}
            data = resp.json()
            posts = data.get("data", {}).get("children", [])
            results = []
            for post in posts:
                p = post.get("data", {})
                results.append({
                    "title": p.get("title", ""),
                    "url": f"https://reddit.com{p.get('permalink', '')}",
                    "subreddit": p.get("subreddit", ""),
                    "author": p.get("author", ""),
                    "created_utc": p.get("created_utc", 0),
                    "selftext": p.get("selftext", "")[:500],
                })
            return {
                "status": "ok",
                "tool": self.name,
                "query": query,
                "result": results,
            }
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}

    def scan(self, query, **kwargs):
        return {"status": "error", "tool": self.name, "error": "Scan not supported"}

    def analyze(self, data, **kwargs):
        return {"note": "Not implemented"}

    def learn(self, feedback, **kwargs):
        pass
