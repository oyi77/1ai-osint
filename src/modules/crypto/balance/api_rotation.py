"""API endpoint rotation with health tracking for blockchain RPC/REST endpoints.

Provides a per-chain endpoint registry with round-robin selection, automatic
disabling after consecutive failures, and timed re-enablement.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Thresholds for endpoint health management
_MAX_CONSECUTIVE_FAILURES = 10
_REENABLE_AFTER_SECONDS = 60.0

# Canonical endpoint inventory per chain (keyed by CoinGecko coin_id)
ENDPOINT_REGISTRY: dict[str, list[str]] = {
    "bitcoin": [
        "https://mempool.space/api",
        "https://blockstream.info/api",
        "https://btcscan.org/api",
        "https://blockchain.info",
        "https://api.blockcypher.com/v1/btc/main",
    ],
    "ethereum": [
        "https://eth.drpc.org",
        "https://ethereum-rpc.publicnode.com",
        "https://cloudflare-eth.com",
        "https://eth.llamarpc.com",
    ],
    "binancecoin": [
        "https://bsc-dataseed.binance.org",
        "https://bsc-dataseed1.binance.org",
        "https://bsc-dataseed2.binance.org",
        "https://bsc-rpc.publicnode.com",
    ],
    "matic-network": [
        "https://polygon-bor-rpc.publicnode.com",
        "https://polygon-rpc.publicnode.com",
        "https://polygon.llamarpc.com",
    ],
    "solana": [
        "https://api.mainnet-beta.solana.com",
        "https://solana-rpc.publicnode.com",
    ],
    "arbitrum": [
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum.llamarpc.com",
        "https://arbitrum-one-rpc.publicnode.com",
    ],
    "optimism": [
        "https://mainnet.optimism.io",
        "https://optimism.llamarpc.com",
        "https://optimism-rpc.publicnode.com",
    ],
    "base": [
        "https://mainnet.base.org",
        "https://base.llamarpc.com",
        "https://base-rpc.publicnode.com",
    ],
    "avalanche": [
        "https://api.avax.network/ext/bc/C/rpc",
        "https://avalanche-c-chain-rpc.publicnode.com",
        "https://avax.meowrpc.com",
    ],
    "fantom": [
        "https://rpc.ftm.tools",
        "https://fantom-rpc.publicnode.com",
    ],
}


@dataclass
class EndpointHealth:
    """Health tracking state for a single endpoint with rate limiting."""

    url: str
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    disabled_at: Optional[float] = None
    # Rate limiter: max requests per second
    max_rps: float = 5.0
    _last_request_time: float = 0.0
    _request_count: int = 0
    _window_start: float = 0.0

    @property
    def is_disabled(self) -> bool:
        """Whether this endpoint is currently disabled."""
        if self.disabled_at is None:
            return False
        if time.monotonic() - self.disabled_at >= _REENABLE_AFTER_SECONDS:
            self.disabled_at = None
            self.consecutive_failures = 0
            logger.info("Re-enabled endpoint: %s", self.url)
            return False
        return True

    def wait_if_needed(self) -> float:
        """Return seconds to wait before next request (0 if no wait needed)."""
        now = time.monotonic()
        # Reset window every second
        if now - self._window_start >= 1.0:
            self._request_count = 0
            self._window_start = now
        # If at rate limit, calculate wait time
        if self._request_count >= self.max_rps:
            wait = 1.0 - (now - self._window_start)
            return max(0, wait)
        return 0.0

    def record_request(self) -> None:
        """Record that a request was made (for rate limiting)."""
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._request_count = 0
            self._window_start = now
        self._request_count += 1
        self._last_request_time = now


class EndpointRotator:
    """Round-robin endpoint selector with health-based auto-disabling.

    Tracks success/failure per endpoint. After 3 consecutive failures,
    an endpoint is disabled for 60 seconds before being re-enabled.

    Example::

        rotator = EndpointRotator(["https://rpc1.example.com", "https://rpc2.example.com"])
        url = rotator.next()
        # ... use url ...
        rotator.report_success(url)
        # or
        rotator.report_failure(url)
    """

    def __init__(self, endpoints: list[str]) -> None:
        if not endpoints:
            raise ValueError("At least one endpoint is required")
        self._endpoints = {url: EndpointHealth(url=url) for url in endpoints}
        self._url_list = list(endpoints)
        self._index = 0

    def next(self) -> str:
        """Return the next healthy endpoint via round-robin.

        Skips disabled endpoints and respects per-endpoint rate limits.
        If all endpoints are disabled, returns the next one anyway (degraded mode).
        """
        n = len(self._url_list)
        best_url = None
        best_wait = float("inf")

        for _ in range(n):
            url = self._url_list[self._index]
            self._index = (self._index + 1) % n
            health = self._endpoints[url]
            if health.is_disabled:
                continue
            wait = health.wait_if_needed()
            if wait < best_wait:
                best_wait = wait
                best_url = url
                if wait == 0:
                    break  # Found an endpoint with no wait — use it immediately

        if best_url is not None:
            return best_url

        # All disabled — find the one closest to re-enable
        now = time.monotonic()
        best_reattempt_url = None
        best_time_left = float("inf")
        for url in self._url_list:
            health = self._endpoints[url]
            if health.disabled_at is not None:
                time_left = _REENABLE_AFTER_SECONDS - (now - health.disabled_at)
                if time_left < best_time_left:
                    best_time_left = time_left
                    best_reattempt_url = url
        if best_reattempt_url:
            if (
                not hasattr(self, "_last_degraded_log")
                or time.monotonic() - self._last_degraded_log > 30
            ):
                logger.warning(
                    "All endpoints disabled — next re-enable in %.0fs",
                    max(0, best_time_left),
                )
                self._last_degraded_log = time.monotonic()
        url = best_reattempt_url or self._url_list[self._index]
        self._index = (self._index + 1) % n
        return url

    def get_wait_time(self, url: str) -> float:
        """Return seconds to wait before using this endpoint."""
        health = self._endpoints.get(url)
        if health is None:
            return 0.0
        return health.wait_if_needed()

    def record_request(self, url: str) -> None:
        """Record a request was made to this endpoint (for rate limiting)."""
        health = self._endpoints.get(url)
        if health:
            health.record_request()

    def report_success(self, url: str) -> None:
        """Record a successful request for the given endpoint."""
        health = self._endpoints.get(url)
        if health is None:
            return
        health.success_count += 1
        health.consecutive_failures = 0

    def report_failure(self, url: str) -> None:
        """Record a failed request for the given endpoint."""
        health = self._endpoints.get(url)
        if health is None:
            return
        # is_disabled handles re-enable after _REENABLE_AFTER_SECONDS
        if health.is_disabled:
            return
        health.failure_count += 1
        health.consecutive_failures += 1
        if (
            health.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES
            and health.disabled_at is None
        ):
            health.disabled_at = time.monotonic()
            logger.warning(
                "Disabled endpoint %s after %d consecutive failures",
                url,
                health.consecutive_failures,
            )

    def get_health(self, url: str) -> Optional[EndpointHealth]:
        """Return health info for a specific endpoint."""
        return self._endpoints.get(url)

    @property
    def endpoints(self) -> list[str]:
        """All registered endpoint URLs."""
        return list(self._url_list)

    @property
    def healthy_count(self) -> int:
        """Number of currently healthy (non-disabled) endpoints."""
        return sum(1 for h in self._endpoints.values() if not h.is_disabled)


def create_rotators() -> dict[str, EndpointRotator]:
    """Create an EndpointRotator for every chain in the registry.

    Returns:
        Dict mapping CoinGecko coin_id to its EndpointRotator.
    """
    return {chain: EndpointRotator(urls) for chain, urls in ENDPOINT_REGISTRY.items()}
