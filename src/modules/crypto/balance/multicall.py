"""Batch balance checking via JSON-RPC native batching.

Sends multiple eth_getBalance calls as a JSON array in one HTTP request.
All EVM JSON-RPC endpoints support batch requests natively — no ABI encoding needed.

This is ~5x faster than individual calls (1 HTTP round-trip instead of N).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from src.modules.crypto.balance.chains import ChainConfig

logger = logging.getLogger(__name__)

_TIMEOUT = 15


@dataclass
class BatchBalanceResult:
    """Result of a batch balance check."""
    address: str
    balance_wei: int
    error: Optional[str] = None


async def batch_check_balances(
    addresses: list[str],
    chain: ChainConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> list[BatchBalanceResult]:
    """Check native balances for multiple EVM addresses in one JSON-RPC batch call.

    Sends N eth_getBalance requests as a JSON array. The RPC server processes
    all requests and returns all results in one HTTP response.

    Args:
        addresses: List of EVM addresses (0x...).
        chain: Chain config with rpc_url.
        client: Optional shared httpx client.

    Returns:
        List of BatchBalanceResult, one per address.
    """
    if not chain.rpc_url or not addresses:
        return [BatchBalanceResult(address=a, balance_wei=0, error="No RPC URL") for a in addresses]

    # Build batch request: one eth_getBalance per address
    batch = [
        {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, "latest"], "id": i}
        for i, addr in enumerate(addresses)
    ]

    try:
        _created = client is None
        if _created:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            resp = await client.post(chain.rpc_url, json=batch)
            resp.raise_for_status()
            results = resp.json()

            # Results may be out of order; map by id
            id_to_result: dict[int, dict] = {}
            for r in results:
                if isinstance(r, dict) and "id" in r:
                    id_to_result[r["id"]] = r

            output: list[BatchBalanceResult] = []
            for i, addr in enumerate(addresses):
                r = id_to_result.get(i)
                if r is None:
                    output.append(BatchBalanceResult(address=addr, balance_wei=0, error="No response"))
                elif "error" in r:
                    output.append(BatchBalanceResult(address=addr, balance_wei=0, error=r["error"].get("message", "RPC error")))
                else:
                    try:
                        balance = int(r["result"], 16)
                        output.append(BatchBalanceResult(address=addr, balance_wei=balance))
                    except (ValueError, TypeError) as e:
                        output.append(BatchBalanceResult(address=addr, balance_wei=0, error=str(e)))
            return output
        finally:
            if _created:
                await client.aclose()
    except Exception as e:
        logger.warning("Batch balance check failed for %s: %s", chain.name, e)
        return [BatchBalanceResult(address=a, balance_wei=0, error=str(e)) for a in addresses]
