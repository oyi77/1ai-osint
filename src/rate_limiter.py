"""Rate limiter for API calls using token bucket algorithm."""

import json
import time
from pathlib import Path
from typing import Optional


class RateLimiter:
    """Token bucket rate limiter with JSON persistence."""

    def __init__(
        self,
        state_file: Optional[Path] = None,
        requests_per_minute: int = 60,
        burst: int = 10,
    ):
        """
        Args:
            state_file: Path to persist rate limiter state.
            requests_per_minute: Sustained rate limit.
            burst: Maximum burst size above sustained rate.
        """
        self.state_file = state_file or Path(".osint_rate_limit.json")
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.burst = burst
        self._state: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        """Load persisted state from disk."""
        if self.state_file.exists():
            try:
                self._state = json.loads(self.state_file.read_text())
            except (json.JSONDecodeError, OSError):
                self._state = {}

    def _save(self) -> None:
        """Persist state to disk."""
        self.state_file.write_text(json.dumps(self._state))

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
        """
        Attempt to acquire tokens. Returns wait time in seconds (0 if immediately available).

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

    def wait(self, key: str = "default", tokens: int = 1) -> None:
        """Acquire tokens, sleeping if necessary."""
        wait_time = self.acquire(key, tokens)
        if wait_time > 0:
            time.sleep(wait_time)

    def reset(self, key: Optional[str] = None) -> None:
        """Reset rate limiter state for a key or all keys."""
        if key:
            self._state.pop(key, None)
        else:
            self._state.clear()
        self._save()

    def get_remaining(self, key: str = "default") -> float:
        """Get remaining tokens for a key."""
        bucket = self._get_bucket(key)
        self._refill(bucket)
        return bucket["tokens"]
