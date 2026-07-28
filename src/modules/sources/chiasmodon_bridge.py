"""Bridge adapter: wraps chiasmodon OSINTTool sources to produce RawLeak objects."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from src.modules.sources.base import RawLeak

logger = logging.getLogger(__name__)

# Map of chiasmodon source names to their module/class paths
_CHIASMODON_SOURCES = {
    "hibp": "src.vendor.chiasmodon.hibp:HIBPTool",
    "shodan": "src.vendor.chiasmodon.shodan:ShodanTool",
    "scylla": "src.vendor.chiasmodon.leak_scylla:ScyllaTool",
    "leakcheck": "src.vendor.chiasmodon.leak_leakcheck:LeakCheckTool",
    "breachdirectory": "src.vendor.chiasmodon.leak_breachdirectory:BreachDirectoryTool",
    "snusbase": "src.vendor.chiasmodon.leak_snusbase:SnusbaseTool",
    "intelx": "src.vendor.chiasmodon.leak_intelx:IntelXTool",
    "dehashed": "src.vendor.chiasmodon.leak_dehashed:DeHashedTool",
    "pastebin": "src.vendor.chiasmodon.leak_pastebin:PastebinTool",
    "reddit_leak": "src.vendor.chiasmodon.leak_reddit:RedditLeakTool",
}


class ChiasmodonBridge:
    """Adapts a chiasmodon OSINTTool to the BaseLeakSource interface.

    Wraps the synchronous search() method in an async context and converts
    the result dict into RawLeak objects.
    """

    def __init__(self, source_name: str, tool_instance: Any):
        self._source_name = source_name
        self._tool = tool_instance

    async def fetch_raw_leaks(self, query: str = "private key mnemonic") -> list[RawLeak]:
        """Run the chiasmodon tool's search() and convert results to RawLeak."""
        leaks: list[RawLeak] = []
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, lambda: self._tool.search(query))
            if not isinstance(result, dict):
                return leaks
            if result.get("status") != "ok":
                return leaks
            for item in result.get("result", []):
                text = json.dumps(item) if isinstance(item, dict) else str(item)
                leaks.append(
                    RawLeak(
                        text=text,
                        source_name=f"chiasmodon_{self._source_name}",
                        source_url="",
                    )
                )
        except Exception as exc:
            logger.debug("Chiasmodon bridge '%s' error: %s", self._source_name, exc)
        return leaks

    async def search_for_address(self, address: str) -> list[RawLeak]:
        """Search chiasmodon source for a specific address."""
        return await self.fetch_raw_leaks(query=address)


def _load_chiasmodon_tool(source_name: str) -> object | None:
    """Lazy-load a chiasmodon tool by name."""
    spec = _CHIASMODON_SOURCES.get(source_name)
    if not spec:
        return None
    module_path, class_name = spec.rsplit(":", 1)
    try:
        import importlib

        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        return cls()
    except Exception as exc:
        logger.debug("Failed to load chiasmodon source '%s': %s", source_name, exc)
        return None


def get_chiasmodon_sources() -> dict[str, ChiasmodonBridge]:
    """Load all available chiasmodon sources as bridges."""
    bridges: dict[str, ChiasmodonBridge] = {}
    for name in _CHIASMODON_SOURCES:
        tool = _load_chiasmodon_tool(name)
        if tool:
            bridges[f"chiasmodon_{name}"] = ChiasmodonBridge(name, tool)
    return bridges
