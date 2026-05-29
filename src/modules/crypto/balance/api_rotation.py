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
_MAX_CONSECUTIVE_FAILURES = 50
_REENABLE_AFTER_SECONDS = 60.0

# Canonical endpoint inventory per chain (keyed by CoinGecko coin_id)
ENDPOINT_REGISTRY: dict[str, list[str]] = {
    "bitcoin": [
        "https://mempool.space/api",
        "https://blockstream.info/api",
        "https://blockchain.info",
    ],
    "ethereum": [
        "https://rpc.ankr.com/eth",
        "https://ethereum-rpc.publicnode.com",
        "https://cloudflare-eth.com",
        "https://eth.drpc.org",
        "https://eth-mainnet.public.blastapi.io",
    ],
    "binancecoin": [
        "https://bsc-dataseed.binance.org",
        "https://bsc-dataseed1.binance.org",
        "https://bsc-dataseed2.binance.org",
        "https://rpc.ankr.com/bsc",
        "https://bsc-rpc.publicnode.com",
        "https://bsc.drpc.org",
    ],
    "matic-network": [
        "https://rpc.ankr.com/polygon",
        "https://polygon-bor-rpc.publicnode.com",
        "https://polygon-rpc.publicnode.com",
        "https://polygon.drpc.org",
    ],
    "solana": [
        "https://api.mainnet-beta.solana.com",
        "https://solana-rpc.publicnode.com",
    ],
}


@dataclass
class EndpointHealth:
    """Health tracking state for a single endpoint."""
    url: str
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    disabled_at: Optional[float] = None

    @property
    def is_disabled(self) -> bool:
        """Whether this endpoint is currently disabled."""
        if self.disabled_at is None:
            return False
        # Re-enable after cooldown period
        if time.monotonic() - self.disabled_at >= _REENABLE_AFTER_SECONDS:
            self.disabled_at = None
            self.consecutive_failures = 0
            logger.info("Re-enabled endpoint: %s", self.url)
            return False
        return True


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

        Skips disabled endpoints. If all endpoints are disabled, returns
        the next one anyway (degraded mode) to avoid total stall.
        """
        n = len(self._url_list)
        for _ in range(n):
            url = self._url_list[self._index]
            self._index = (self._index + 1) % n
            health = self._endpoints[url]
            if not health.is_disabled:
                return url

        # All disabled — return next round-robin pick (degraded mode)
        url = self._url_list[self._index]
        self._index = (self._index + 1) % n
        logger.warning("All endpoints disabled, using degraded endpoint: %s", url)
        return url

    def report_success(self, url: str) -> None:
        """Record a successful request for the given endpoint."""
        health = self._endpoints.get(url)
        if health is None:
            return
        health.success_count += 1
        health.consecutive_failures = 0

    def report_failure(self, url: str) -> None:
        """Record a failed request for the given endpoint.

        After `_MAX_CONSECUTIVE_FAILURES` consecutive failures, the
        endpoint is disabled for `_REENABLE_AFTER_SECONDS`.
        """
        health = self._endpoints.get(url)
        if health is None:
            return
        health.failure_count += 1
        health.consecutive_failures += 1
        if health.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
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
