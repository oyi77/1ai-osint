"""JSON file-based caching for OSINT query results."""

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class Cache:
    """Simple JSON file cache with TTL support."""

    def __init__(self, cache_dir: Path | None = None, default_ttl: int = 3600):
        """Args:
        cache_dir: Directory for cache files. Defaults to .osint_cache
        default_ttl: Default time-to-live in seconds (1 hour).

        """
        self.cache_dir = cache_dir or Path(".osint_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

    def _key_path(self, key: str) -> Path:
        """Convert a cache key to a filesystem-safe path."""
        safe_key = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Any | None:
        """Retrieve a cached value. Returns None if missing or expired."""
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if data.get("expires_at", 0) < time.time():
                path.unlink(missing_ok=True)
                return None
            return data.get("value")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value in the cache."""
        path = self._key_path(key)
        ttl = ttl if ttl is not None else self.default_ttl
        data = {
            "key": key,
            "value": value,
            "created_at": time.time(),
            "expires_at": time.time() + ttl,
        }
        path.write_text(json.dumps(data, default=str))

    def delete(self, key: str) -> bool:
        """Remove a cached entry. Returns True if it existed."""
        path = self._key_path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def clear(self) -> int:
        """Remove all cache entries. Returns count of removed files."""
        count = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink()
            count += 1
        return count

    def has(self, key: str) -> bool:
        """Check if a non-expired entry exists."""
        return self.get(key) is not None
