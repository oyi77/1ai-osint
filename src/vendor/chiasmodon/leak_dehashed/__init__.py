import os

import requests

from src.vendor.chiasmodon.base import OSINTTool


class DeHashedTool(OSINTTool):
    """DeHashed breach database search."""

    name = "dehashed"
    API_URL = "https://api.dehashed.com/search"

    def search(self, query, **kwargs):
        api_key = os.environ.get("DEHASHED_API_KEY")
        if not api_key:
            return {
                "status": "error",
                "tool": self.name,
                "error": "Missing DEHASHED_API_KEY",
            }
        try:
            resp = requests.get(
                self.API_URL,
                params={"query": query, "size": kwargs.get("size", 100)},
                auth=tuple(api_key.split(":", 1)) if ":" in api_key else (api_key, ""),
                headers={"Accept": "application/json"},
                timeout=30,
            )
            if resp.status_code != 200:
                return {
                    "status": "error",
                    "tool": self.name,
                    "error": f"HTTP {resp.status_code}",
                }
            data = resp.json()
            entries = data.get("entries", [])
            return {
                "status": "ok",
                "tool": self.name,
                "query": query,
                "result": [dict(e) if hasattr(e, "items") else e for e in entries],
                "total": data.get("balance", len(entries)),
            }
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}

    def scan(self, query, **kwargs):
        return {"status": "error", "tool": self.name, "error": "Scan not supported"}

    def analyze(self, data, **kwargs):
        return {"note": "Not implemented"}

    def learn(self, feedback, **kwargs):
        pass
