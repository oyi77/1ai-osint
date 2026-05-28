import os
import requests
from src.vendor.chiasmodon.base import OSINTTool

class ScyllaTool(OSINTTool):
    name = "scylla"
    API_URL = "https://scylla.sh/search"
    API_KEY = os.environ.get("SCYLLA_API_KEY")

    def search(self, query, **kwargs):
        if not self.API_KEY:
            return {"status": "error", "tool": self.name, "error": "Missing SCYLLA_API_KEY"}
        headers = {"Authorization": f"Bearer {self.API_KEY}"}
        try:
            resp = requests.get(self.API_URL, params={"q": query}, headers=headers, timeout=30)
            if resp.status_code != 200:
                return {"status": "error", "tool": self.name, "error": f"HTTP {resp.status_code}"}
            return {"status": "ok", "tool": self.name, "query": query, "result": resp.json().get("results", [])}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}
    def scan(self, query, **kwargs):
        return {"status": "error", "tool": self.name, "error": "Scan not supported"}
    def analyze(self, data, **kwargs):
        return {"note": "Not implemented"}
    def learn(self, feedback, **kwargs):
        pass
