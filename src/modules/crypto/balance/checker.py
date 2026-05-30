"""Balance checking across multiple blockchains.

Uses free public APIs (no API keys required):
- BTC: blockstream.info REST API
- ETH/BSC/Polygon: Public JSON-RPC endpoints
- SOL: Solana public RPC
- Prices: CoinGecko free API
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from src.modules.crypto.balance.chains import (
    BITCOIN,
    SOLANA,
    ChainConfig,
    ChainType,
    TokenContract,
)

logger = logging.getLogger(__name__)

# Timeout for API calls
_TIMEOUT = 15

# CoinGecko price cache: {coin_id: (price, timestamp)}
_price_cache: dict[str, tuple[float, float]] = {}
_PRICE_CACHE_TTL = 60  # seconds


@dataclass
class BalanceResult:
    """Result of a balance check for a single address."""
    address: str
    chain: str
    symbol: str
    balance: float          # Native token balance
    balance_raw: int        # Raw balance in smallest unit (wei, satoshi, lamports)
    usd_price: float        # Current USD price per token
    usd_value: float        # Total USD value
    derivation_path: str    # How this address was derived
    error: Optional[str] = None


async def check_btc_balance(
    address: str,
    api_url: str = "https://mempool.space/api",
    derivation_path: str = "",
    client: Optional[httpx.AsyncClient] = None,
) -> BalanceResult:
    """Check BTC balance via multiple free API formats.

    Supports: mempool.space, blockstream.info, blockchain.info, blockcypher.
    Auto-detects response format.
    """
    try:
        _created_client = client is None
        if _created_client:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            # Try standard format first (mempool.space, blockstream.info)
            resp = await client.get(f"{api_url}/address/{address}")
            resp.raise_for_status()
            data = resp.json()

            balance_sat = _parse_btc_balance(data)
        finally:
            if _created_client:
                await client.aclose()

        balance_btc = balance_sat / 1e8

        return BalanceResult(
            address=address,
            chain=BITCOIN.name,
            symbol=BITCOIN.symbol,
            balance=balance_btc,
            balance_raw=balance_sat,
            usd_price=0.0,
            usd_value=0.0,
            derivation_path=derivation_path,
        )
    except Exception as e:
        return BalanceResult(
            address=address,
            chain=BITCOIN.name,
            symbol=BITCOIN.symbol,
            balance=0.0, balance_raw=0,
            usd_price=0.0, usd_value=0.0,
            derivation_path=derivation_path,
            error=str(e),
        )


def _parse_btc_balance(data: dict) -> int:
    """Parse BTC balance from various API response formats.

    Supports: mempool.space, blockstream.info, blockcypher, blockchain.info
    """
    # Format 1: mempool.space / blockstream.info (chain_stats)
    if "chain_stats" in data:
        funded = data["chain_stats"].get("funded_txo_sum", 0)
        spent = data["chain_stats"].get("spent_txo_sum", 0)
        return funded - spent

    # Format 2: blockcypher (balance in satoshis)
    if "balance" in data and "unconfirmed_balance" in data:
        return data["balance"] + data.get("unconfirmed_balance", 0)

    # Format 3: blockchain.info (final_balance)
    if "final_balance" in data:
        return data["final_balance"]

    # Format 4: generic balance field
    if "balance" in data:
        return int(data["balance"])

    return 0


async def check_evm_balance(
    address: str,
    chain: ChainConfig,
    derivation_path: str = "",
    client: Optional[httpx.AsyncClient] = None,
) -> BalanceResult:
    """Check balance on an EVM-compatible chain (ETH, BSC, Polygon) via JSON-RPC."""
    if not chain.rpc_url:
        return BalanceResult(
            address=address, chain=chain.name, symbol=chain.symbol,
            balance=0.0, balance_raw=0, usd_price=0.0, usd_value=0.0,
            derivation_path=derivation_path, error="No RPC URL configured",
        )

    try:
        _created_client = client is None
        if _created_client:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 1,
            }
            resp = await client.post(chain.rpc_url, json=payload)
            resp.raise_for_status()
            data = resp.json()

            if "error" in data:
                raise ValueError(data["error"].get("message", "RPC error"))

            balance_wei = int(data["result"], 16)
            balance = balance_wei / (10 ** chain.decimals)

            return BalanceResult(
                address=address,
                chain=chain.name,
                symbol=chain.symbol,
                balance=balance,
                balance_raw=balance_wei,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path=derivation_path,
            )
        finally:
            if _created_client:
                await client.aclose()
    except Exception as e:
        return BalanceResult(
            address=address, chain=chain.name, symbol=chain.symbol,
            balance=0.0, balance_raw=0, usd_price=0.0, usd_value=0.0,
            derivation_path=derivation_path, error=str(e),
        )


def encode_balance_of(address: str) -> str:
    """Encode ERC-20 balanceOf(address) call data."""
    addr_clean = address.lower().replace("0x", "")
    return "0x70a08231" + addr_clean.zfill(64)


async def check_evm_token_balances(
    address: str,
    chain: ChainConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> list[dict]:
    """Check ERC-20 token balances for a single address on an EVM chain.

    Returns list of dicts with keys: symbol, balance_raw, decimals, balance.
    Only includes tokens with non-zero balance.
    """
    if not chain.rpc_url or not chain.tokens:
        return []

    try:
        _created_client = client is None
        if _created_client:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            results = []
            batch = []
            for i, token in enumerate(chain.tokens):
                data = encode_balance_of(address)
                batch.append({
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{"to": token.address, "data": data}, "latest"],
                    "id": i,
                })

            resp = await client.post(chain.rpc_url, json=batch)
            resp.raise_for_status()
            batch_results = resp.json()

            id_to_result: dict[int, dict] = {}
            for r in batch_results:
                if isinstance(r, dict) and "id" in r:
                    id_to_result[r["id"]] = r

            for i, token in enumerate(chain.tokens):
                r = id_to_result.get(i)
                if r is None or "error" in r or "result" not in r:
                    continue
                try:
                    balance_raw = int(r["result"], 16)
                    if balance_raw > 0:
                        results.append({
                            "symbol": token.symbol,
                            "balance_raw": balance_raw,
                            "decimals": token.decimals,
                            "balance": balance_raw / (10 ** token.decimals),
                        })
                except (ValueError, TypeError):
                    continue

            return results
        finally:
            if _created_client:
                await client.aclose()
    except Exception as e:
        logger.debug("Token balance check failed for %s on %s: %s", address[:10], chain.name, e)
        return []


async def check_sol_balance(
    address: str,
    rpc_url: str = "https://api.mainnet-beta.solana.com",
    derivation_path: str = "",
    client: Optional[httpx.AsyncClient] = None,
) -> BalanceResult:
    """Check SOL balance via Solana JSON-RPC."""
    try:
        _created_client = client is None
        if _created_client:
            client = httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "getBalance",
                "params": [address],
                "id": 1,
            }
            resp = await client.post(rpc_url, json=payload)
            resp.raise_for_status()
            data = resp.json()

            if "error" in data:
                raise ValueError(data["error"].get("message", "RPC error"))

            balance_lamports = data["result"]["value"]
            balance_sol = balance_lamports / 1e9

            return BalanceResult(
                address=address,
                chain=SOLANA.name,
                symbol=SOLANA.symbol,
                balance=balance_sol,
                balance_raw=balance_lamports,
                usd_price=0.0,
                usd_value=0.0,
                derivation_path=derivation_path,
            )
        finally:
            if _created_client:
                await client.aclose()
    except Exception as e:
        return BalanceResult(
            address=address, chain=SOLANA.name, symbol=SOLANA.symbol,
            balance=0.0, balance_raw=0, usd_price=0.0, usd_value=0.0,
            derivation_path=derivation_path, error=str(e),
        )


async def check_balance(
    address: str,
    chain: ChainConfig,
    derivation_path: str = "",
    client: Optional[httpx.AsyncClient] = None,
) -> BalanceResult:
    """Route balance check to the appropriate chain-specific function."""
    if chain.chain_type == ChainType.BITCOIN:
        return await check_btc_balance(address, chain.api_url or "", derivation_path, client=client)
    elif chain.chain_type == ChainType.EVM:
        return await check_evm_balance(address, chain, derivation_path, client=client)
    elif chain.chain_type == ChainType.SOLANA:
        return await check_sol_balance(address, chain.rpc_url or "", derivation_path, client=client)
    else:
        return BalanceResult(
            address=address, chain=chain.name, symbol=chain.symbol,
            balance=0.0, balance_raw=0, usd_price=0.0, usd_value=0.0,
            derivation_path=derivation_path,
            error=f"Unsupported chain type: {chain.chain_type}",
        )


async def get_usd_prices(
    coin_ids: list[str],
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, float]:
    """Fetch current USD prices from CoinGecko with 60-second TTL caching.

    Args:
        coin_ids: List of CoinGecko coin IDs (e.g. ["ethereum", "bitcoin"]).
        client: Optional pre-configured httpx.AsyncClient for connection pooling.

    Returns:
        Dict mapping coin_id to USD price.
    """
    if not coin_ids:
        return {}

    now = time.monotonic()
    unique_ids = list(set(coin_ids))

    # Separate cached vs uncached
    cached: dict[str, float] = {}
    uncached: list[str] = []
    for cid in unique_ids:
        if cid in _price_cache:
            price, ts = _price_cache[cid]
            if now - ts < _PRICE_CACHE_TTL:
                cached[cid] = price
            else:
                uncached.append(cid)
        else:
            uncached.append(cid)

    # Fetch uncached prices
    if uncached:
        try:
            _created_client = client is None
            if _created_client:
                client = httpx.AsyncClient(timeout=_TIMEOUT)
            try:
                ids_str = ",".join(uncached)
                resp = await client.get(
                    "https://api.coingecko.com/api/v3/simple/price",
                    params={"ids": ids_str, "vs_currencies": "usd"},
                )
                resp.raise_for_status()
                data = resp.json()
                for cid in uncached:
                    price = data.get(cid, {}).get("usd", 0.0)
                    _price_cache[cid] = (price, now)
                    cached[cid] = price
            finally:
                if _created_client:
                    await client.aclose()
        except Exception as e:
            logger.warning("CoinGecko price fetch failed: %s", e)
            for cid in uncached:
                cached.setdefault(cid, 0.0)

    return {cid: cached.get(cid, 0.0) for cid in coin_ids}


def apply_usd_prices(results: list[BalanceResult], prices: dict[str, float]) -> list[BalanceResult]:
    """Apply USD prices to balance results in-place and compute usd_value."""
    from src.modules.crypto.balance.chains import CHAIN_MAP

    for r in results:
        chain_cfg = CHAIN_MAP.get(r.chain.lower())
        if chain_cfg and chain_cfg.coin_id in prices:
            r.usd_price = prices[chain_cfg.coin_id]
            r.usd_value = r.balance * r.usd_price

    return results


def clear_price_cache() -> None:
    """Clear the CoinGecko price cache. Useful for testing or forced refresh."""
    _price_cache.clear()
