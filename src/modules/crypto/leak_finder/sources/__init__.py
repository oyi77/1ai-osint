"""Leak finder source adapters.

All sources are auto-discovered by the coordinator via _discover_sources().
To add a new source, create a file named *_source.py with a class ending
in 'Source' that has a `fetch_raw_leaks()` method. No registration needed.
"""
from src.modules.crypto.leak_finder.sources.github_source import RawLeak

__all__ = ["RawLeak"]
