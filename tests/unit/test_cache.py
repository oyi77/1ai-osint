"""Tests for cache module."""

import json
import os
import threading
import time

from src.core.cache import Cache


class TestCache:
    def test_set_and_get(self, test_cache):
        test_cache.set("key1", {"data": "value"})
        result = test_cache.get("key1")
        assert result == {"data": "value"}

    def test_get_missing(self, test_cache):
        assert test_cache.get("nonexistent") is None

    def test_ttl_expiry(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=0)
        cache.set("key1", "value")
        # TTL=0 means expires immediately
        time.sleep(0.01)
        assert cache.get("key1") is None

    def test_has_expiry(self, tmp_path):
        """has() must be expiry-aware, not just presence-aware."""
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=0)
        cache.set("key1", "value")
        time.sleep(0.01)
        assert cache.has("key1") is False

    def test_delete(self, test_cache):
        test_cache.set("key1", "value")
        assert test_cache.delete("key1") is True
        assert test_cache.get("key1") is None

    def test_delete_nonexistent(self, test_cache):
        assert test_cache.delete("nonexistent") is False

    def test_clear(self, test_cache):
        test_cache.set("a", 1)
        test_cache.set("b", 2)
        count = test_cache.clear()
        assert count == 2
        assert test_cache.get("a") is None

    def test_clear_removes_temp_files(self, test_cache):
        test_cache.set("a", 1)
        (test_cache.cache_dir / "orphan.tmp").write_text("junk")
        count = test_cache.clear()
        assert count == 2
        assert not (test_cache.cache_dir / "orphan.tmp").exists()

    def test_has(self, test_cache):
        test_cache.set("key1", "value")
        assert test_cache.has("key1") is True
        assert test_cache.has("missing") is False

    def test_set_writes_atomically(self, tmp_path):
        """A set must never leave a partially-written cache file behind."""
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        cache.set("key1", {"data": "value"})
        # No leftover temp files after a successful write.
        assert list(cache.cache_dir.glob("*.tmp")) == []
        # Entry is a fully-formed JSON file.
        path = cache._key_path("key1")
        data = json.loads(path.read_text())
        assert data["value"] == {"data": "value"}
        assert cache.get("key1") == {"data": "value"}

    def test_prune_removes_expired(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        cache.set("fresh", "v")
        # Manually backdate an entry.
        stale = cache._key_path("stale")
        stale.write_text(json.dumps({"key": "stale", "value": "old", "expires_at": time.time() - 1}))
        removed = cache.prune()
        assert removed == 1
        assert cache.get("fresh") == "v"
        assert not stale.exists()

    def test_prune_removes_corrupt_and_temp(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        cache.set("a", 1)
        corrupt = cache.cache_dir / "corrupt.json"
        corrupt.write_text("{not valid json")
        orphan_tmp = cache.cache_dir / "orphan.tmp"
        orphan_tmp.write_text("partial")
        # Backdate past the 60s age-gate so prune() treats it as orphaned.
        os.utime(orphan_tmp, (time.time() - 120, time.time() - 120))
        removed = cache.prune()
        assert removed == 2
        assert not corrupt.exists()
        assert not orphan_tmp.exists()
        assert cache.get("a") == 1

    def test_prune_keeps_valid_entries(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.prune() == 0
        assert cache.get("a") == 1
        assert cache.get("b") == 2

    def test_prune_triggered_every_n_writes(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        stale = cache._key_path("stale")
        stale.write_text(json.dumps({"key": "stale", "value": "old", "expires_at": time.time() - 1}))
        # Write until the auto-prune fires; the stale entry must disappear.
        for i in range(50):
            cache.set(f"k{i}", i)
        assert not stale.exists()

    def test_concurrent_sets(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        errors = []

        def writer(n: int) -> None:
            try:
                for i in range(20):
                    cache.set(f"key-{n}-{i}", {"n": n, "i": i})
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(list(cache.cache_dir.glob("*.tmp"))) == 0
        for n in range(8):
            assert cache.get(f"key-{n}-0") == {"n": n, "i": 0}

    def test_prune_keeps_fresh_temp(self, tmp_path):
        cache = Cache(cache_dir=tmp_path / "cache", default_ttl=60)
        fresh_tmp = cache.cache_dir / "in-flight.tmp"
        fresh_tmp.write_text("partial")
        assert cache.prune() == 0
        assert fresh_tmp.exists()
