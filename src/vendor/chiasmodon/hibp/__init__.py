import os
from typing import Any

import requests

from src.vendor.chiasmodon.base import OSINTTool


class HIBPTool(OSINTTool):
    """OSINT wrapper for HaveIBeenPwned (HIBP) API."""

    name = "hibp"
    API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
    API_KEY = os.environ.get("HIBP_API_KEY")

    def search(self, query: str, **kwargs) -> dict[str, Any]:
        headers = {"hibp-api-key": self.API_KEY or "", "user-agent": "1ai-osint"}
        try:
            resp = requests.get(
                self.API_URL.format(query),
                headers=headers,
                params={"truncateResponse": "false"},
            )
            if resp.status_code == 404:
                return {"status": "ok", "tool": self.name, "result": []}
            resp.raise_for_status()
            return {"status": "ok", "tool": self.name, "result": resp.json()}
        except Exception as e:
            return {"status": "error", "tool": self.name, "error": str(e)}

    def scan(self, query: str, **kwargs) -> dict[str, Any]:
        return {
            "status": "error",
            "tool": self.name,
            "error": "Scan not supported for HIBP",
        }

    def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        return {"note": "No advanced analysis implemented for HIBP"}

    def learn(self, feedback: Any, **kwargs) -> None:
        pass
