"""Multi-source OSINT leak aggregator."""

import logging

from src.vendor.chiasmodon.base import OSINTTool

logger = logging.getLogger(__name__)


class LeakAggregatorTool(OSINTTool):
    """Aggregates results from multiple OSINT leak sources."""

    name = "leak_aggregator"

    def __init__(self):
        self.feedback = {"false_positives": [], "false_negatives": []}
        self._sources = None

    def _get_sources(self):
        """Lazy-load available leak source tools."""
        if self._sources is not None:
            return self._sources
        sources = []
        for module_path, class_name in [
            ("src.vendor.chiasmodon.hibp", "HIBPTool"),
            ("src.vendor.chiasmodon.shodan", "ShodanTool"),
            ("src.vendor.chiasmodon.leak_scylla", "ScyllaTool"),
            ("src.vendor.chiasmodon.leak_leakcheck", "LeakCheckTool"),
            ("src.vendor.chiasmodon.leak_breachdirectory", "BreachDirectoryTool"),
            ("src.vendor.chiasmodon.leak_snusbase", "SnusbaseTool"),
            ("src.vendor.chiasmodon.leak_intelx", "IntelXTool"),
            ("src.vendor.chiasmodon.leak_dehashed", "DeHashedTool"),
            ("src.vendor.chiasmodon.leak_pastebin", "PastebinTool"),
            ("src.vendor.chiasmodon.leak_reddit", "RedditLeakTool"),
        ]:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                sources.append(cls())
            except Exception:
                pass
        self._sources = sources
        return sources

    def search(self, query, **kwargs):
        sources = self._get_sources()
        if not sources:
            return {"status": "ok", "tool": self.name, "query": query, "result": [], "note": "No sources available"}
        all_results = []
        errors = []
        for source in sources:
            try:
                result = source.search(query, **kwargs)
                if result.get("status") == "ok":
                    items = result.get("result", [])
                    for item in items:
                        item["_source"] = source.name
                    all_results.extend(items)
                else:
                    errors.append({"source": source.name, "error": result.get("error", "unknown")})
            except Exception as e:
                errors.append({"source": source.name, "error": str(e)})
        return {
            "status": "ok",
            "tool": self.name,
            "query": query,
            "result": all_results,
            "sources_queried": len(sources),
            "errors": errors,
        }

    def scan(self, query, **kwargs):
        return self.search(query, **kwargs)

    def analyze(self, data, **kwargs):
        if not data:
            return {"note": "No data to analyze"}
        sources = {}
        for item in data:
            src = item.get("_source", "unknown")
            sources.setdefault(src, []).append(item)
        return {
            "total_results": len(data),
            "by_source": {k: len(v) for k, v in sources.items()},
            "sources_active": list(sources.keys()),
        }

    def learn(self, feedback, **kwargs):
        if isinstance(feedback, dict):
            if "false_positive" in feedback:
                self.feedback["false_positives"].append(feedback["false_positive"])
            if "false_negative" in feedback:
                self.feedback["false_negatives"].append(feedback["false_negative"])
