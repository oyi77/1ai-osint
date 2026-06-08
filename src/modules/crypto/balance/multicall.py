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

from src.modules.crypto.balance.chains import ChainConfig, TokenContract
from src.modules.crypto.balance.checker import encode_balance_of

logger = logging.getLogger(__name__)

_TIMEOUT = 30


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
        return [
            BatchBalanceResult(address=a, balance_wei=0, error="No RPC URL")
            for a in addresses
        ]

    all_results: list[BatchBalanceResult] = []
    _created = client is None
    if _created:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        # Process in chunks to avoid overwhelming free endpoints
        for chunk_start in range(0, len(addresses), _EVM_CHUNK_SIZE):
            chunk = addresses[chunk_start : chunk_start + _EVM_CHUNK_SIZE]
            batch = [
                {
                    "jsonrpc": "2.0",
                    "method": "eth_getBalance",
                    "params": [addr, "latest"],
                    "id": i,
                }
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
                        all_results.append(
                            BatchBalanceResult(
                                address=addr, balance_wei=0, error="No response"
                            )
                        )
                    elif "error" in r:
                        all_results.append(
                            BatchBalanceResult(
                                address=addr,
                                balance_wei=0,
                                error=r["error"].get("message", "RPC error"),
                            )
                        )
                    else:
                        try:
                            balance = int(r["result"], 16)
                            all_results.append(
                                BatchBalanceResult(address=addr, balance_wei=balance)
                            )
                        except (ValueError, TypeError) as e:
                            all_results.append(
                                BatchBalanceResult(
                                    address=addr, balance_wei=0, error=str(e)
                                )
                            )
            except Exception as e:
                logger.warning("EVM batch chunk failed for %s: %s", chain.name, e)
                all_results.extend(
                    BatchBalanceResult(address=a, balance_wei=0, error=str(e))
                    for a in chunk
                )

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

    _created = client is None
    if _created:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        # Process in chunks of 100 (getMultipleAccountsInfo limit)
        for chunk_start in range(0, len(addresses), 100):
            chunk = addresses[chunk_start : chunk_start + 100]

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
                    fallback = await _sol_batch_fallback(chunk, rpc_url, client)
                    results.extend(fallback)
                    continue

                values = data.get("result", {}).get("value", [])
                for i, addr in enumerate(chunk):
                    if i < len(values) and values[i] is not None:
                        lamports = values[i].get("lamports", 0)
                        results.append(
                            BatchBalanceResult(address=addr, balance_wei=lamports)
                        )
                    elif i < len(values):
                        # Account doesn't exist
                        results.append(BatchBalanceResult(address=addr, balance_wei=0))
                    else:
                        results.append(
                            BatchBalanceResult(
                                address=addr, balance_wei=0, error="No response"
                            )
                        )
            except Exception as e:
                # On HTTP error (e.g. 403 from WAF), fall back to individual calls
                logger.debug(
                    "SOL getMultipleAccounts failed (%s), falling back to individual calls",
                    e,
                )
                try:
                    fallback = await _sol_batch_fallback(chunk, rpc_url, client)
                    results.extend(fallback)
                except Exception as e2:
                    logger.warning("SOL fallback also failed: %s", e2)
                    results.extend(
                        BatchBalanceResult(address=a, balance_wei=0, error=str(e2))
                        for a in chunk
                    )
    finally:
        if _created:
            await client.aclose()

    return results


async def _sol_batch_fallback(
    addresses: list[str],
    rpc_url: str,
    client: httpx.AsyncClient,
) -> list[BatchBalanceResult]:
    """Fallback: individual getBalance calls (one HTTP request per address)."""
    output: list[BatchBalanceResult] = []
    for i, addr in enumerate(addresses):
        if i > 0:
            await asyncio.sleep(0.05)  # Rate-limit individual calls
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "getBalance",
                "params": [addr],
                "id": i,
            }
            resp = await client.post(rpc_url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                output.append(
                    BatchBalanceResult(
                        address=addr,
                        balance_wei=0,
                        error=data["error"].get("message", "RPC error"),
                    )
                )
            else:
                lamports = data.get("result", {}).get("value", 0)
                output.append(BatchBalanceResult(address=addr, balance_wei=lamports))
        except Exception as e:
            output.append(BatchBalanceResult(address=addr, balance_wei=0, error=str(e)))
    return output


@dataclass
class TokenBalanceResult:
    """Result of a token balance check."""

    address: str
    token_symbol: str
    token_address: str
    balance_raw: int  # Raw balance in token's smallest unit
    decimals: int
    error: Optional[str] = None

    @property
    def balance(self) -> float:
        """Human-readable balance."""
        return self.balance_raw / (10**self.decimals) if self.balance_raw > 0 else 0.0


async def batch_check_token_balances(
    addresses: list[str],
    tokens: list[TokenContract],
    chain: ChainConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> list[TokenBalanceResult]:
    """Check ERC-20 token balances for multiple addresses via eth_call batching.

    Sends one JSON-RPC batch per chunk of addresses, with one eth_call per
    address × token combination.

    Args:
        addresses: List of EVM addresses (0x...).
        tokens: List of token contracts to check.
        chain: Chain config with rpc_url.
        client: Optional shared httpx client.

    Returns:
        List of TokenBalanceResult for each address × token pair with non-zero balance.
    """
    if not chain.rpc_url or not addresses or not tokens:
        return []

    results: list[TokenBalanceResult] = []
    _created = client is None
    if _created:
        client = httpx.AsyncClient(timeout=_TIMEOUT)

    try:
        # Build eth_call requests for all address × token pairs
        # Chunk to avoid overwhelming endpoints
        calls: list[tuple[str, TokenContract, int]] = []  # (address, token, id)
        call_id = 0
        for addr in addresses:
            for token in tokens:
                calls.append((addr, token, call_id))
                call_id += 1

        # Process in chunks of 50 calls (same as EVM_CHUNK_SIZE * 2)
        chunk_size = 50
        for chunk_start in range(0, len(calls), chunk_size):
            chunk = calls[chunk_start : chunk_start + chunk_size]
            batch = []
            for addr, token, cid in chunk:
                data = encode_balance_of(addr)
                batch.append(
                    {
                        "jsonrpc": "2.0",
                        "method": "eth_call",
                        "params": [{"to": token.address, "data": data}, "latest"],
                        "id": cid,
                    }
                )

            try:
                resp = await client.post(chain.rpc_url, json=batch)
                resp.raise_for_status()
                batch_results = resp.json()

                id_to_result: dict[int, dict] = {}
                for r in batch_results:
                    if isinstance(r, dict) and "id" in r:
                        id_to_result[r["id"]] = r

                for addr, token, cid in chunk:
                    r = id_to_result.get(cid)
                    if r is None:
                        continue  # Skip — no response for this call
                    if "error" in r:
                        # Token call failed (contract might not exist on this chain)
                        continue
                    try:
                        hex_result = r.get("result", "0x0")
                        balance_raw = int(hex_result, 16) if hex_result else 0
                        if balance_raw > 0:
                            results.append(
                                TokenBalanceResult(
                                    address=addr,
                                    token_symbol=token.symbol,
                                    token_address=token.address,
                                    balance_raw=balance_raw,
                                    decimals=token.decimals,
                                )
                            )
                    except (ValueError, TypeError):
                        continue
            except Exception as e:
                logger.warning("Token batch chunk failed for %s: %s", chain.name, e)

            await asyncio.sleep(0.1)  # Delay between chunks
    finally:
        if _created:
            await client.aclose()

    return results
