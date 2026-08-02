"""Shared loader for scan-result JSON files used by the web route modules.

All route modules previously re-implemented the same file scan (search
Path.cwd() and ~/.1ai-osint for *.json, skip known non-scan files, parse each
file, flatten dict-or-list) on every request. This module centralizes that
logic and memoizes the result for a short TTL so repeated reads within a
request window (e.g. the reports list + detail pages) do not re-parse the
same files.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_SKIP_PATTERNS = (".osint_rate_limit", "package-lock", "package", "tsconfig", "cov")
_TTL_SECONDS = 30.0

_lock = threading.Lock()
_cached_key: tuple[str, str] | None = None
_cached_at: float = 0.0
_cached_items: list[tuple[Path, dict]] = []


def scan_dirs_key() -> tuple[str, str]:
    """Return a cache key identifying the data directories at call time."""
    return (str(Path.cwd()), str(Path.home() / ".1ai-osint"))


def load_scan_items() -> list[tuple[Path, dict]]:
    """Return ``(file, item)`` pairs for scan-result JSON files.

    Files are scanned in ``Path.cwd()`` and ``~/.1ai-osint``, sorted by name,
    minus the known non-scan patterns. A dict file yields one item; a list
    file yields its dict elements; anything malformed or unreadable is
    skipped. Results are memoized for ``_TTL_SECONDS``; callers must not
    mutate the returned items.
    """
    key = scan_dirs_key()
    global _cached_key, _cached_at, _cached_items
    with _lock:
        now = time.monotonic()
        if _cached_key == key and now - _cached_at < _TTL_SECONDS:
            return list(_cached_items)
        items: list[tuple[Path, dict]] = []
        for search_dir in (Path.cwd(), Path.home() / ".1ai-osint"):
            if not search_dir.exists():
                continue
            for f in sorted(search_dir.glob("*.json")):
                if any(p in f.name for p in _SKIP_PATTERNS):
                    continue
                try:
                    data = json.loads(f.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                if isinstance(data, dict):
                    items.append((f, data))
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            items.append((f, item))
        _cached_key = key
        _cached_at = now
        _cached_items = items
        return list(items)


class TTLCache:
    """Minimal thread-safe TTL cache for derived route data."""

    def __init__(self, ttl: float = _TTL_SECONDS) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._key: tuple[str, str] | None = None
        self._stamp: float = 0.0
        self._value: list[dict] = []

    def get(self, key: tuple[str, str]) -> list[dict] | None:
        with self._lock:
            if self._key == key and time.monotonic() - self._stamp < self._ttl:
                return self._value
            return None

    def set(self, key: tuple[str, str], value: list[dict]) -> None:
        with self._lock:
            self._key = key
            self._stamp = time.monotonic()
            self._value = value
