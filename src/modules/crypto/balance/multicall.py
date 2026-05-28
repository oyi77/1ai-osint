"""Batch balance checking via JSON-RPC batching.

Sends multiple eth_getBalance calls in a single HTTP request.
Simple, reliable, no complex ABI encoding needed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from src.modules.crypto.balance.chains import ChainConfig, ChainType

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
    """Check native balances for multiple addresses in ONE HTTP request via JSON-RPC batching.

    Works on any EVM or Solana JSON-RPC endpoint — no special contract needed.
    """
    if not chain.rpc_url or not addresses:
        return [BatchBalanceResult(address=a, balance_wei=0, error="No RPC URL") for a in addresses]

    try:
        _created = client is None
        if _created:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            if chain.chain_type == ChainType.SOLANA:
                return await _batch_solana(addresses, chain, client)
            else:
                return await _batch_evm(addresses, chain, client)
        finally:
            if _created:
                await client.aclose()
    except Exception as e:
        logger.warning("Batch balance failed for %s: %s", chain.name, e)
        return [BatchBalanceResult(address=a, balance_wei=0, error=str(e)) for a in addresses]


async def _batch_evm(
    addresses: list[str],
    chain: ChainConfig,
    client: httpx.AsyncClient,
) -> list[BatchBalanceResult]:
    """Batch eth_getBalance calls for EVM chains via JSON-RPC batch."""
    # Build batch request: one eth_getBalance per address
    batch = [
        {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, "latest"], "id": i}
        for i, addr in enumerate(addresses)
    ]

    resp = await client.post(chain.rpc_url, json=batch)
    resp.raise_for_status()
    responses = resp.json()

    # Map responses back to addresses by id
    results_by_id: dict[int, dict] = {}
    if isinstance(responses, list):
        for r in responses:
            results_by_id[r.get("id", -1)] = r
    else:
        # Single response fallback
        results_by_id[0] = responses

    results = []
    for i, addr in enumerate(addresses):
        resp_data = results_by_id.get(i, {})
        if "error" in resp_data:
            results.append(BatchBalanceResult(
                address=addr, balance_wei=0,
                error=resp_data["error"].get("message", "RPC error"),
            ))
        elif "result" in resp_data:
            results.append(BatchBalanceResult(
                address=addr,
                balance_wei=int(resp_data["result"], 16),
            ))
        else:
            results.append(BatchBalanceResult(address=addr, balance_wei=0, error="No response"))

    return results


async def _batch_solana(
    addresses: list[str],
    chain: ChainConfig,
    client: httpx.AsyncClient,
) -> list[BatchBalanceResult]:
    """Batch getBalance calls for Solana via JSON-RPC batch."""
    batch = [
        {"jsonrpc": "2.0", "method": "getBalance", "params": [addr], "id": i}
        for i, addr in enumerate(addresses)
    ]

    resp = await client.post(chain.rpc_url, json=batch)
    resp.raise_for_status()
    responses = resp.json()

    results_by_id: dict[int, dict] = {}
    if isinstance(responses, list):
        for r in responses:
            results_by_id[r.get("id", -1)] = r
    else:
        results_by_id[0] = responses

    results = []
    for i, addr in enumerate(addresses):
        resp_data = results_by_id.get(i, {})
        if "error" in resp_data:
            results.append(BatchBalanceResult(
                address=addr, balance_wei=0,
                error=resp_data["error"].get("message", "RPC error"),
            ))
        elif "result" in resp_data and isinstance(resp_data["result"], dict):
            results.append(BatchBalanceResult(
                address=addr,
                balance_wei=resp_data["result"].get("value", 0),
            ))
        else:
            results.append(BatchBalanceResult(address=addr, balance_wei=0, error="No response"))

    return results
