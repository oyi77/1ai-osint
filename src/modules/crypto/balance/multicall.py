"""Batch balance checking via JSON-RPC native batching.

Sends multiple balance check calls as a JSON array in one HTTP request.
Supports both EVM (eth_getBalance) and Solana (getBalance / getMultipleAccountsInfo).

This is ~5-10x faster than individual calls (1 HTTP round-trip instead of N).
Solana getMultipleAccountsInfo can check up to 100 accounts per call.
"""

from __future__ import annotations

import asyncio
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


_EVM_CHUNK_SIZE = 25  # Max addresses per JSON-RPC batch call (free endpoint friendly)


async def batch_check_balances(
    addresses: list[str],
    chain: ChainConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> list[BatchBalanceResult]:
    """Check native balances for multiple EVM addresses in chunked JSON-RPC batch calls.

    Splits large address lists into chunks of _EVM_CHUNK_SIZE to avoid
    overwhelming free endpoints with massive batch requests.

    Args:
        addresses: List of EVM addresses (0x...).
        chain: Chain config with rpc_url.
        client: Optional shared httpx client.

    Returns:
        List of BatchBalanceResult, one per address.
    """
    if not chain.rpc_url or not addresses:
        return [BatchBalanceResult(address=a, balance_wei=0, error="No RPC URL") for a in addresses]

    all_results: list[BatchBalanceResult] = []
    _created = client is None
    if _created:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        # Process in chunks to avoid overwhelming free endpoints
        for chunk_start in range(0, len(addresses), _EVM_CHUNK_SIZE):
            chunk = addresses[chunk_start:chunk_start + _EVM_CHUNK_SIZE]
            batch = [
                {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, "latest"], "id": i}
                for i, addr in enumerate(chunk)
            ]

            try:
                resp = await client.post(chain.rpc_url, json=batch)
                resp.raise_for_status()
                results = resp.json()

                id_to_result: dict[int, dict] = {}
                for r in results:
                    if isinstance(r, dict) and "id" in r:
                        id_to_result[r["id"]] = r

                for i, addr in enumerate(chunk):
                    r = id_to_result.get(i)
                    if r is None:
                        all_results.append(BatchBalanceResult(address=addr, balance_wei=0, error="No response"))
                    elif "error" in r:
                        all_results.append(BatchBalanceResult(address=addr, balance_wei=0, error=r["error"].get("message", "RPC error")))
                    else:
                        try:
                            balance = int(r["result"], 16)
                            all_results.append(BatchBalanceResult(address=addr, balance_wei=balance))
                        except (ValueError, TypeError) as e:
                            all_results.append(BatchBalanceResult(address=addr, balance_wei=0, error=str(e)))
            except Exception as e:
                logger.warning("EVM batch chunk failed for %s: %s", chain.name, e)
                all_results.extend(BatchBalanceResult(address=a, balance_wei=0, error=str(e)) for a in chunk)

            # Delay between chunks to avoid burst rate limiting
            await asyncio.sleep(0.1)
    finally:
        if _created:
            await client.aclose()

    return all_results


async def batch_check_sol_balances(
    addresses: list[str],
    rpc_url: str = "https://api.mainnet-beta.solana.com",
    client: Optional[httpx.AsyncClient] = None,
) -> list[BatchBalanceResult]:
    """Check SOL balances for multiple addresses in one JSON-RPC batch call.

    Uses getMultipleAccountsInfo (up to 100 per call) for maximum efficiency.
    Falls back to JSON-RPC batching if getMultipleAccountsInfo fails.

    Args:
        addresses: List of Solana addresses (base58).
        rpc_url: Solana RPC endpoint.
        client: Optional shared httpx client.

    Returns:
        List of BatchBalanceResult (balance_lamports in balance_wei field).
    """
    if not addresses:
        return []

    results: list[BatchBalanceResult] = []

    # Process in chunks of 100 (getMultipleAccountsInfo limit)
    for chunk_start in range(0, len(addresses), 100):
        chunk = addresses[chunk_start:chunk_start + 100]

        try:
            _created = client is None
            if _created:
                client = httpx.AsyncClient(timeout=_TIMEOUT)
            try:
                # Use getMultipleAccountsInfo — one call for up to 100 accounts
                payload = {
                    "jsonrpc": "2.0",
                    "method": "getMultipleAccounts",
                    "params": [
                        chunk,
                        {"encoding": "base64"},
                    ],
                    "id": 1,
                }
                resp = await client.post(rpc_url, json=payload)
                resp.raise_for_status()
                data = resp.json()

                if "error" in data:
                    # Fallback to individual batch
                    logger.debug("getMultipleAccounts failed, falling back to batch")
                    assert client is not None
                    fallback = await _sol_batch_fallback(chunk, rpc_url, client)
                    results.extend(fallback)
                    continue

                values = data.get("result", {}).get("value", [])
                for i, addr in enumerate(chunk):
                    if i < len(values) and values[i] is not None:
                        lamports = values[i].get("lamports", 0)
                        results.append(BatchBalanceResult(address=addr, balance_wei=lamports))
                    elif i < len(values):
                        # Account doesn't exist
                        results.append(BatchBalanceResult(address=addr, balance_wei=0))
                    else:
                        results.append(BatchBalanceResult(address=addr, balance_wei=0, error="No response"))
            finally:
                if _created:
                    await client.aclose()
        except Exception as e:
            # On HTTP error (e.g. 403 from WAF), fall back to individual calls
            logger.debug("SOL getMultipleAccounts failed (%s), falling back to individual calls", e)
            try:
                _fb_client = client if client and not client.is_closed else httpx.AsyncClient(timeout=_TIMEOUT)
                _fb_created = _fb_client is not client
                fallback = await _sol_batch_fallback(chunk, rpc_url, _fb_client)
                results.extend(fallback)
                if _fb_created:
                    await _fb_client.aclose()
            except Exception as e2:
                logger.warning("SOL fallback also failed: %s", e2)
                results.extend(BatchBalanceResult(address=a, balance_wei=0, error=str(e2)) for a in chunk)

    return results


async def _sol_batch_fallback(
    addresses: list[str],
    rpc_url: str,
    client: httpx.AsyncClient,
) -> list[BatchBalanceResult]:
    """Fallback: individual getBalance calls (one HTTP request per address)."""
    output: list[BatchBalanceResult] = []
    for i, addr in enumerate(addresses):
        try:
            payload = {"jsonrpc": "2.0", "method": "getBalance", "params": [addr], "id": i}
            resp = await client.post(rpc_url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                output.append(BatchBalanceResult(address=addr, balance_wei=0, error=data["error"].get("message", "RPC error")))
            else:
                lamports = data.get("result", {}).get("value", 0)
                output.append(BatchBalanceResult(address=addr, balance_wei=lamports))
        except Exception as e:
            output.append(BatchBalanceResult(address=addr, balance_wei=0, error=str(e)))
    return output
