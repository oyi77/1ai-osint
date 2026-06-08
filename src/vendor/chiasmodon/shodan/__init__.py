import os
from typing import Any, Dict

import requests

from src.vendor.chiasmodon.base import OSINTTool


class ShodanTool(OSINTTool):
    """OSINT wrapper for Shodan API."""

    name = "shodan"
    API_URL = "https://api.shodan.io/shodan/host/{}"
    API_KEY = os.environ.get("SHODAN_API_KEY")

    def search(self, query: str, **kwargs) -> Dict[str, Any]:
        params = {"key": self.API_KEY}
        try:
            resp = requests.get(self.API_URL.format(query), params=params)
            if resp.status_code == 404:
                return {"status": "ok", "tool": self.name, "result": {}}
            resp.raise_for_status()
            return {"status": "ok", "tool": self.name, "result": resp.json()}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}

    def scan(self, query: str, **kwargs) -> Dict[str, Any]:
        return {
            "status": "error",
            "tool": self.name,
            "error": "Scan not supported for Shodan",
        }

    def analyze(self, data: Any, **kwargs) -> Dict[str, Any]:
        return {"note": "No advanced analysis for Shodan"}

    def learn(self, feedback: Any, **kwargs) -> None:
        pass
