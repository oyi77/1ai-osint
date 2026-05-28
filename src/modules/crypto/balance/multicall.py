"""Batch balance checking via Multicall3 contracts.

Uses tryAggregate() to check multiple addresses in a single eth_call,
dramatically reducing RPC requests and avoiding rate limits.

Reference: tokentools.app batchCheckBalance pattern.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from src.modules.crypto.balance.chains import ChainConfig

logger = logging.getLogger(__name__)

_TIMEOUT = 15

# Multicall3 contract addresses per chain (from tokentools.app)
MULTICALL3: dict[str, str] = {
    "ethereum": "0x5ba1e12693dc8f9c48aad8770482f4739beed696",
    "bnb smart chain": "0xff6fd90a470aaa0c1b8a54681746b07acdfedc9b",
    "polygon": "0xa9fa9a0042e627c769de398f194fd0f301ea1f4f",
}

# getEthBalance(address) selector
_GET_ETH_BALANCE = "4d2301cc"


@dataclass
class BatchBalanceResult:
    """Result of a batch balance check."""
    address: str
    balance_wei: int
    error: Optional[str] = None


def _pad(val: str) -> str:
    """Pad address to 32 bytes (left-pad with zeros)."""
    return val.lower().removeprefix("0x").zfill(64)


def _uint(val: int) -> str:
    """Encode uint256."""
    return hex(val)[2:].zfill(64)


def build_batch_call(addresses: list[str], mc3_addr: str) -> str:
    """Build tryAggregate call data matching tokentools.app pattern.

    tryAggregate(true, (address target, bytes calldata)[])
    where each call = (multicall3, getEthBalance(wallet_addr))
    """
    data = "bce38bd7"                                  # selector
    data += _uint(1)                                   # requireSuccess = true
    data += _uint(0x40)                                # offset to calls array
    data += _uint(len(addresses))                      # array length

    # Each tuple: address target (multicall3) + offset to bytes
    for _ in addresses:
        data += _pad(mc3_addr)                         # target = Multicall3 contract
        data += _uint(0x20)                            # offset to bytes = 32

    # Each calldata: getEthBalance(wallet_address)
    for addr in addresses:
        data += _uint(36)                              # bytes length = 4 + 32
        data += _GET_ETH_BALANCE + _pad(addr)          # selector + address

    return "0x" + data


def decode_batch_result(hex_data: str, count: int) -> list[BatchBalanceResult]:
    """Decode tryAggregate return data.

    Format: (bool success, bytes returnData)[]
    Each returnData = abi.encode(uint256 balance).
    """
    results = []
    clean = hex_data.removeprefix("0x")

    if len(clean) < 128:
        return [BatchBalanceResult(address="", balance_wei=0, error="Empty response")] * count

    idx = 128  # skip offset(32) + length(32)

    for _ in range(count):
        if idx + 192 > len(clean):
            results.append(BatchBalanceResult(address="", balance_wei=0, error="Truncated"))
            continue

        success = int(clean[idx:idx+64], 16) == 1
        idx += 64   # success
        idx += 64   # returnData offset

        if success:
            data_len = int(clean[idx:idx+64], 16)
            idx += 64
            if data_len >= 32 and idx + 64 <= len(clean):
                balance = int(clean[idx:idx+64], 16)
                results.append(BatchBalanceResult(address="", balance_wei=balance))
                idx += ((data_len + 31) // 32) * 64
            else:
                results.append(BatchBalanceResult(address="", balance_wei=0, error="No data"))
        else:
            idx += 64
            results.append(BatchBalanceResult(address="", balance_wei=0, error="Call reverted"))

    return results


async def batch_check_balances(
    addresses: list[str],
    chain: ChainConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> list[BatchBalanceResult]:
    """Check native balances for multiple EVM addresses in one RPC call.

    Falls back to individual eth_getBalance if Multicall3 not available for chain.
    """
    if not chain.rpc_url or not addresses:
        return [BatchBalanceResult(address=a, balance_wei=0, error="No RPC URL") for a in addresses]

    mc3_addr = MULTICALL3.get(chain.name.lower())

    try:
        _created = client is None
        if _created:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            if mc3_addr:
                call_data = build_batch_call(addresses, mc3_addr)
                payload = {
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{"to": mc3_addr, "data": call_data}, "latest"],
                    "id": 1,
                }
                resp = await client.post(chain.rpc_url, json=payload)
                resp.raise_for_status()
                result = resp.json()

                if "error" in result:
                    raise ValueError(result["error"].get("message", "RPC error"))

                decoded = decode_batch_result(result.get("result", "0x"), len(addresses))
                for i, addr in enumerate(addresses):
                    if i < len(decoded):
                        decoded[i].address = addr
                return decoded
            else:
                # Fallback: individual eth_getBalance calls
                return await _individual_balances(addresses, chain, client)
        finally:
            if _created:
                await client.aclose()
    except Exception as e:
        logger.warning("Multicall failed for %s: %s", chain.name, e)
        return [BatchBalanceResult(address=a, balance_wei=0, error=str(e)) for a in addresses]


async def _individual_balances(
    addresses: list[str],
    chain: ChainConfig,
    client: httpx.AsyncClient,
) -> list[BatchBalanceResult]:
    """Fallback: check balances individually."""
    results = []
    for addr in addresses:
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [addr, "latest"],
                "id": 1,
            }
            resp = await client.post(chain.rpc_url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                results.append(BatchBalanceResult(address=addr, balance_wei=0, error=data["error"]["message"]))
            else:
                results.append(BatchBalanceResult(address=addr, balance_wei=int(data["result"], 16)))
        except Exception as e:
            results.append(BatchBalanceResult(address=addr, balance_wei=0, error=str(e)))
    return results
