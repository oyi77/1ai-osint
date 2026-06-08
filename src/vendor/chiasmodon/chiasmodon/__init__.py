import logging
import os
from typing import Any, Dict

from src.vendor.chiasmodon.base import OSINTTool


class ChiasmodonTool(OSINTTool):
    """OSINT wrapper for Chiasmodon API."""

    name = "chiasmodon"

    def __init__(self, token=None):
        self.token = token or os.environ.get("CHIASMODON_TOKEN")

    def search(self, query: str, **kwargs) -> Dict[str, Any]:
        try:
            from src.vendor.chiasmodon.chiasmodon.pychiasmodon import Chiasmodon

            client = Chiasmodon(token=self.token, check_token=False, debug=False)
            result = client.search(
                query=query,
                method=kwargs.get("method", "domain"),
                view_type=kwargs.get("view_type", "full"),
                timeout=kwargs.get("timeout", 60),
                limit=kwargs.get("limit", 10000),
            )
            return {
                "status": "ok",
                "tool": self.name,
                "query": query,
                "result_count": len(result) if result else 0,
                "results": [
                    dict(r) if hasattr(r, "items") else str(r) for r in (result or [])
                ],
            }
        except Exception as e:
            logging.error(f"Chiasmodon search error: {e}")
            return {"status": "error", "tool": self.name, "error": str(e)}

    def scan(self, query: str, **kwargs) -> Dict[str, Any]:
        return self.search(query, **kwargs)

    def analyze(self, data: Any, **kwargs) -> Dict[str, Any]:
        return {"note": "No advanced analysis implemented for Chiasmodon"}

    def learn(self, feedback: Any, **kwargs) -> None:
        pass


class OSINTAggregatorTool(OSINTTool):
    """Aggregates results from multiple OSINT providers."""

    name = "osint_aggregator"

    def __init__(self):
        from src.vendor.chiasmodon.leak_aggregator import LeakAggregatorTool

        self._aggregator = LeakAggregatorTool()

    def search(self, query: str, **kwargs) -> Dict[str, Any]:
        return self._aggregator.search(query, **kwargs)

    def scan(self, query: str, **kwargs) -> Dict[str, Any]:
        return self._aggregator.scan(query, **kwargs)

    def analyze(self, data: Any, **kwargs) -> Dict[str, Any]:
        return self._aggregator.analyze(data, **kwargs)

    def learn(self, feedback: Any, **kwargs) -> None:
        self._aggregator.learn(feedback, **kwargs)
