import os
import requests
from src.vendor.chiasmodon.base import OSINTTool

class LeakCheckTool(OSINTTool):
    name = "leakcheck"
    API_URL = "https://leakcheck.io/api/search"
    API_KEY = os.environ.get("LEAKCHECK_API_KEY")

    def search(self, query, **kwargs):
        if not self.API_KEY:
            return {"status": "error", "tool": self.name, "error": "Missing LEAKCHECK_API_KEY"}
        try:
            resp = requests.get(self.API_URL, params={"key": self.API_KEY, "query": query}, timeout=30)
            if resp.status_code != 200:
                return {"status": "error", "tool": self.name, "error": f"HTTP {resp.status_code}"}
            return {"status": "ok", "tool": self.name, "query": query, "result": resp.json().get("result", [])}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}
    def scan(self, query, **kwargs):
        return {"status": "error", "tool": self.name, "error": "Scan not supported"}
    def analyze(self, data, **kwargs):
        return {"note": "Not implemented"}
    def learn(self, feedback, **kwargs):
        pass
