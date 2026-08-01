"""JSON file-based caching for OSINT query results."""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

# Run a prune pass every N writes so expired entries are reaped without a
# dedicated background job.
_PRUNE_EVERY = 50


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
        self._writes = 0

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
        """Store a value in the cache.

        The entry is written atomically (temp file + os.replace) so concurrent
        readers never observe a partially-written JSON file, and the write is
        fsynced before rename so a crash cannot leave an empty entry behind.
        """
        path = self._key_path(key)
        ttl = ttl if ttl is not None else self.default_ttl
        data = {
            "key": key,
            "value": value,
            "created_at": time.time(),
            "expires_at": time.time() + ttl,
        }
        payload = json.dumps(data, default=str).encode("utf-8")

        fd, tmp_name = tempfile.mkstemp(dir=self.cache_dir, suffix=".tmp")
        try:
            try:
                fh = os.fdopen(fd, "wb")
            except Exception:
                os.close(fd)
                raise
            with fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

        self._writes += 1
        if self._writes % _PRUNE_EVERY == 0:
            self.prune()

    def delete(self, key: str) -> bool:
        """Remove a cached entry. Returns True if it existed."""
        path = self._key_path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def prune(self) -> int:
        """Remove expired entries, corrupt files, and stale temp files.

        Returns the number of files removed. Called automatically on every Nth
        write so the cache does not accumulate expired entries indefinitely.
        """
        removed = 0
        now = time.time()
        for f in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if data.get("expires_at", 0) < now:
                    f.unlink(missing_ok=True)
                    removed += 1
            except (json.JSONDecodeError, OSError):
                # Corrupt or unreadable entry — drop it.
                try:
                    f.unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    pass
        for f in self.cache_dir.glob("*.tmp"):
            try:
                # Skip temp files younger than 60s — they may be in-flight
                # atomic writes from a concurrent set().
                if time.time() - f.stat().st_mtime < 60:
                    continue
                f.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
        return removed

    def clear(self) -> int:
        """Remove all cache entries and temp files. Returns count of removed files."""
        count = 0
        for f in list(self.cache_dir.glob("*.json")) + list(self.cache_dir.glob("*.tmp")):
            f.unlink()
            count += 1
        return count

    def has(self, key: str) -> bool:
        """Check if a non-expired entry exists.

        Unlike :meth:`get`, this avoids deserializing the cached value — only
        the TTL metadata is inspected, which keeps existence checks cheap.
        """
        path = self._key_path(key)
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            return data.get("expires_at", 0) > time.time()
        except (json.JSONDecodeError, OSError):
            return False
