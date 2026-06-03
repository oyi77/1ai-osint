"""Shared leak sources module.

Auto-discovers source files in this directory. Each source must:
- Be named *_source.py
- Contain a class ending in 'Source' with a fetch_raw_leaks() method
"""

from __future__ import annotations
import importlib
import pathlib
from src.modules.sources.base import RawLeak, BaseLeakSource

__all__ = ["RawLeak", "BaseLeakSource", "ALL_SOURCES", "discover_sources"]


def discover_sources() -> dict[str, type]:
    """Auto-discover source classes from this directory."""
    source_map: dict[str, type] = {}
    sources_dir = pathlib.Path(__file__).parent
    for py_file in sorted(sources_dir.glob("*_source.py")):
        module_name = py_file.stem
        key = module_name.replace("_source", "")
        try:
            module = importlib.import_module(f"src.modules.sources.{module_name}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and attr_name.endswith("Source")
                    and attr_name != "RawLeak"
                    and hasattr(attr, "fetch_raw_leaks")
                ):
                    source_map[key] = attr
                    break
        except Exception:
            pass
    return source_map


_SOURCE_MAP = discover_sources()
ALL_SOURCES = list(_SOURCE_MAP.keys())
