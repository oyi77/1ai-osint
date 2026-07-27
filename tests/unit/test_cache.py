"""Tests for cache module."""

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

    def test_has(self, test_cache):
        test_cache.set("key1", "value")
        assert test_cache.has("key1") is True
        assert test_cache.has("missing") is False
