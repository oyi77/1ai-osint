"""Batch balance checking via Multicall3 contracts.

Uses tryAggregate() to check multiple addresses in a single eth_call,
dramatically reducing RPC requests and avoiding rate limits.

Reference: https://www.multicall3.com/
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from src.modules.crypto.balance.chains import ChainConfig

logger = logging.getLogger(__name__)

_TIMEOUT = 15

# Multicall3 deployed at the same address on all EVM chains
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"

# tryAggregate(bool,(address,bytes)[]) selector
_TRY_AGGREGATE = "bce38bd7"
# getEthBalance(address) selector
_GET_ETH_BALANCE = "4d2301cc"


@dataclass
class BatchBalanceResult:
    """Result of a batch balance check."""
    address: str
    balance_wei: int
    error: Optional[str] = None


def _pad_addr(addr: str) -> str:
    """Left-pad address to 32 bytes."""
    return addr.lower().removeprefix("0x").zfill(64)


def _pad_uint(val: int) -> str:
    """Left-pad uint256 to 32 bytes."""
    return hex(val)[2:].zfill(64)


def encode_try_aggregate(addresses: list[str]) -> str:
    """Encode Multicall3.tryAggregate(false, calls) where each call is getEthBalance(addr).

    ABI layout:
      selector (4 bytes)
      requireSuccess: bool = false (32 bytes)
      offset to calls[]: 0x40 (32 bytes)
      calls[] length: N (32 bytes)
      call[0..N-1]: each tuple = (address target, offset to bytes, bytes length, bytes data)
    """
    data = _TRY_AGGREGATE
    data += _pad_uint(0)          # requireSuccess = false
    data += _pad_uint(0x40)       # offset to calls array

    n = len(addresses)
    data += _pad_uint(n)          # array length

    # Each tuple: address(32) + bytes_offset(32) + bytes_len(32) + bytes_data(32)
    # bytes_data = getEthBalance selector(4) + address(32) = 36 bytes
    # So each tuple = 4 * 32 = 128 bytes
    # Offsets are relative to the start of each tuple
    for addr in addresses:
        data += _pad_addr(MULTICALL3)   # target = Multicall3 contract
        data += _pad_uint(0x20)         # offset to bytes = 32 (skip address field)

    for addr in addresses:
        data += _pad_uint(36)           # bytes length = 4 + 32
        data += _GET_ETH_BALANCE + _pad_addr(addr)  # getEthBalance(address)

    return "0x" + data


def decode_try_aggregate(hex_data: str, count: int) -> list[BatchBalanceResult]:
    """Decode tryAggregate return data into balance results.

    Return format: (bool success, bytes returnData)[]
    Each returnData is abi.encode(uint256) for getEthBalance.
    """
    results = []
    clean = hex_data.removeprefix("0x")

    if len(clean) < 128:
        return [BatchBalanceResult(address="", balance_wei=0, error="Empty response")] * count

    # Skip array offset (32) + array length (32)
    idx = 128

    for _ in range(count):
        if idx + 192 > len(clean):
            results.append(BatchBalanceResult(address="", balance_wei=0, error="Truncated"))
            continue

        success = int(clean[idx:idx+64], 16) == 1
        idx += 64  # success bool
        idx += 64  # returnData offset

        if success:
            data_len = int(clean[idx:idx+64], 16)
            idx += 64
            if data_len >= 32 and idx + 64 <= len(clean):
                balance = int(clean[idx:idx+64], 16)
                results.append(BatchBalanceResult(address="", balance_wei=balance))
                # Advance past the actual data (round up to 32-byte boundary)
                idx += ((data_len + 31) // 32) * 64
            else:
                results.append(BatchBalanceResult(address="", balance_wei=0, error="No data"))
        else:
            idx += 64  # skip returnData length even on failure
            results.append(BatchBalanceResult(address="", balance_wei=0, error="Call reverted"))

    # Fill in addresses
    for i, addr_idx in enumerate(range(min(len(results), count))):
        pass  # addresses are passed separately

    return results


async def batch_check_balances(
    addresses: list[str],
    chain: ChainConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> list[BatchBalanceResult]:
    """Check native balances for multiple EVM addresses in one RPC call.

    Args:
        addresses: List of EVM addresses (0x...).
        chain: Chain config with rpc_url.
        client: Optional shared httpx client.

    Returns:
        List of BatchBalanceResult, one per address.
    """
    if not chain.rpc_url or not addresses:
        return [BatchBalanceResult(address=a, balance_wei=0, error="No RPC URL") for a in addresses]

    try:
        _created = client is None
        if _created:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            call_data = encode_try_aggregate(addresses)
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{"to": MULTICALL3, "data": call_data}, "latest"],
                "id": 1,
            }
            resp = await client.post(chain.rpc_url, json=payload)
            resp.raise_for_status()
            result = resp.json()

            if "error" in result:
                raise ValueError(result["error"].get("message", "RPC error"))

            decoded = decode_try_aggregate(result.get("result", "0x"), len(addresses))

            # Map addresses to results
            for i, addr in enumerate(addresses):
                if i < len(decoded):
                    decoded[i].address = addr
                else:
                    decoded.append(BatchBalanceResult(address=addr, balance_wei=0, error="Index out of range"))

            return decoded
        finally:
            if _created:
                await client.aclose()
    except Exception as e:
        logger.warning("Multicall failed for %s: %s", chain.name, e)
        return [BatchBalanceResult(address=a, balance_wei=0, error=str(e)) for a in addresses]
