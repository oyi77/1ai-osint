import os
import requests
from src.vendor.chiasmodon.base import OSINTTool

class IntelXTool(OSINTTool):
    name = "intelx"
    API_URL = "https://2.intelx.io/phonebook/search"
    API_KEY = os.environ.get("INTELX_API_KEY")

    def search(self, query, **kwargs):
        if not self.API_KEY:
            return {"status": "error", "tool": self.name, "error": "Missing INTELX_API_KEY"}
        headers = {"x-key": self.API_KEY}
        try:
            resp = requests.post(self.API_URL, json={"term": query, "maxresults": 100}, headers=headers, timeout=30)
            if resp.status_code != 200:
                return {"status": "error", "tool": self.name, "error": f"HTTP {resp.status_code}"}
            return {"status": "ok", "tool": self.name, "query": query, "result": resp.json().get("records", [])}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}
    def scan(self, query, **kwargs):
        return {"status": "error", "tool": self.name, "error": "Scan not supported"}
    def analyze(self, data, **kwargs):
        return {"note": "Not implemented"}
    def learn(self, feedback, **kwargs):
        pass
