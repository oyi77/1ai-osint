"""Rate limiters for outbound API calls and inbound HTTP requests.

``RateLimiter`` is the token-bucket limiter for *outbound* calls to external
sources (disk-persisted so limits survive restarts). ``RequestLimiter`` is a
separate, in-memory limiter for *inbound* HTTP requests (per-client API
throttling); it never touches disk.
"""

import asyncio
import json
import time
from pathlib import Path


class RateLimiter:
    """Token bucket rate limiter with JSON persistence."""

    def __init__(
        self,
        state_file: Path | None = None,
        requests_per_minute: int = 60,
        burst: int = 10,
    ):
        """Args:
        state_file: Path to persist rate limiter state.
        requests_per_minute: Sustained rate limit.
        burst: Maximum burst size above sustained rate.

        """
        self.state_file = state_file or Path(".osint_rate_limit.json")
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.burst = burst
        self._state: dict[str, dict] = {}
        self._dirty = False
        self._last_flush = 0.0
        self._flush_interval = 1.0  # seconds between disk writes
        self._load()

    def _load(self) -> None:
        """Load persisted state from disk."""
        if self.state_file.exists():
            try:
                self._state = json.loads(self.state_file.read_text())
            except (json.JSONDecodeError, OSError):
                self._state = {}

    def _save(self) -> None:
        """Mark state as dirty. Actual disk write is batched."""
        self._dirty = True
        now = time.time()
        if now - self._last_flush >= self._flush_interval:
            self._flush()

    def _flush(self) -> None:
        """Force-write dirty state to disk."""
        if self._dirty:
            self.state_file.write_text(json.dumps(self._state))
            self._dirty = False
            self._last_flush = time.time()

    def _get_bucket(self, key: str) -> dict:
        """Get or create a token bucket for the given key."""
        if key not in self._state:
            self._state[key] = {
                "tokens": float(self.burst),
                "last_refill": time.time(),
            }
        return self._state[key]

    def _refill(self, bucket: dict) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(
            float(self.burst),
            bucket["tokens"] + elapsed * self.rate,
        )
        bucket["last_refill"] = now

    def acquire(self, key: str = "default", tokens: int = 1) -> float:
        """Attempt to acquire tokens. Returns wait time in seconds (0 if immediately available).

        Args:
            key: Rate limit key (e.g., API name).
            tokens: Number of tokens to acquire.

        Returns:
            Seconds to wait before request can proceed (0 = go now).

        """
        bucket = self._get_bucket(key)
        self._refill(bucket)

        if bucket["tokens"] >= tokens:
            bucket["tokens"] -= tokens
            self._save()
            return 0.0

        # Calculate wait time
        deficit = tokens - bucket["tokens"]
        wait_time = deficit / self.rate
        self._save()
        return wait_time

    async def acquire_async(self, key: str = "default", tokens: int = 1) -> float:
        """Async version of acquire. Non-blocking sleep when tokens unavailable.

        Args:
            key: Rate limit key (e.g., API name).
            tokens: Number of tokens to acquire.

        Returns:
            Seconds actually waited (0 = went immediately).

        """
        bucket = self._get_bucket(key)
        self._refill(bucket)

        if bucket["tokens"] >= tokens:
            bucket["tokens"] -= tokens
            self._save()
            return 0.0

        # Calculate wait time and sleep asynchronously
        deficit = tokens - bucket["tokens"]
        wait_time = deficit / self.rate
        self._save()
        await asyncio.sleep(wait_time)
        # Refill after wait and consume
        self._refill(bucket)
        bucket["tokens"] -= tokens
        self._save()
        return wait_time

    def wait(self, key: str = "default", tokens: int = 1) -> None:
        """Acquire tokens, sleeping if necessary."""
        wait_time = self.acquire(key, tokens)
        if wait_time > 0:
            time.sleep(wait_time)

    def reset(self, key: str | None = None) -> None:
        """Reset rate limiter state for a key or all keys."""
        if key:
            self._state.pop(key, None)
        else:
            self._state.clear()
        self._flush()

    def get_remaining(self, key: str = "default") -> float:
        """Get remaining tokens for a key."""
        bucket = self._get_bucket(key)
        self._refill(bucket)
        return bucket["tokens"]

    def close(self) -> None:
        """Flush any pending state to disk before shutdown."""
        self._flush()


class RequestLimiter:
    """In-memory token bucket for inbound HTTP requests.

    Unlike :class:`RateLimiter` (outbound, disk-persisted) this gate is
    deliberately stateless across restarts: it protects the API from a
    burst of requests from a single client and is safe to reset freely.
    Uses ``time.monotonic`` so wall-clock changes cannot skew refills.
    """

    def __init__(self, requests_per_minute: int = 60, burst: int = 30):
        """Args:
        requests_per_minute: Sustained per-key rate.
        burst: Maximum burst size above the sustained rate.

        """
        self.rate = max(requests_per_minute, 1) / 60.0  # tokens per second
        self.burst = max(burst, 1)
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill)

    def _refill(self, key: str) -> float:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.burst), now))
        tokens = min(float(self.burst), tokens + (now - last) * self.rate)
        self._buckets[key] = (tokens, now)
        return tokens

    def allow(self, key: str = "default") -> bool:
        """Return True if the key may make one more request right now."""
        tokens = self._refill(key)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, time.monotonic())
            return True
        return False

    def reset(self, key: str | None = None) -> None:
        """Drop the bucket for ``key`` (or all buckets when omitted)."""
        if key:
            self._buckets.pop(key, None)
        else:
            self._buckets.clear()
