"""Tests for rate limiter module."""

from src.rate_limiter import RateLimiter


class TestRateLimiter:
    def test_acquire_immediate(self, test_rate_limiter):
        wait = test_rate_limiter.acquire("test")
        assert wait == 0.0

    def test_burst_limit(self, tmp_path):
        limiter = RateLimiter(
            state_file=tmp_path / "rl.json",
            requests_per_minute=60,
            burst=2,
        )
        # First two should be immediate
        assert limiter.acquire("test") == 0.0
        assert limiter.acquire("test") == 0.0
        # Third should require wait
        wait = limiter.acquire("test")
        assert wait > 0.0

    def test_get_remaining(self, test_rate_limiter):
        initial = test_rate_limiter.get_remaining("test")
        test_rate_limiter.acquire("test")
        after = test_rate_limiter.get_remaining("test")
        assert after < initial

    def test_reset(self, test_rate_limiter):
        test_rate_limiter.acquire("test")
        test_rate_limiter.reset("test")
        remaining = test_rate_limiter.get_remaining("test")
        assert remaining == test_rate_limiter.burst

    def test_different_keys(self, test_rate_limiter):
        test_rate_limiter.acquire("key1")
        remaining_key2 = test_rate_limiter.get_remaining("key2")
        assert remaining_key2 == test_rate_limiter.burst
