import os

import requests

from src.vendor.chiasmodon.base import OSINTTool


class GithubDorkTool(OSINTTool):
    name = "githubdork"
    SEARCH_URL = "https://api.github.com/search/code"

    def search(self, query, **kwargs):
        # Read lazily at call time so a token set after import is picked up.
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            return {
                "status": "error",
                "tool": self.name,
                "error": "Missing GITHUB_TOKEN",
            }
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        try:
            resp = requests.get(self.SEARCH_URL, headers=headers, params={"q": query}, timeout=30)
            if resp.status_code != 200:
                return {
                    "status": "error",
                    "tool": self.name,
                    "error": f"HTTP {resp.status_code}",
                }
            results = [
                {
                    "name": i.get("name"),
                    "path": i.get("path"),
                    "repository": i.get("repository", {}).get("full_name"),
                    "html_url": i.get("html_url"),
                }
                for i in resp.json().get("items", [])
            ]
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
