"""Address derivation from mnemonic phrases and private keys.

Supports BTC (BIP-44/49/84), ETH, BSC, Polygon, and SOL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from bip_utils import (
    Bip39SeedGenerator,
    Bip39MnemonicValidator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)

from src.modules.crypto.balance.chains import (
    BITCOIN,
    ETHEREUM,
    SOLANA,
    ChainConfig,
    ALL_CHAINS,
)


@dataclass
class DerivedAddress:
    """A derived wallet address with metadata."""
    address: str
    chain: str           # e.g. "Ethereum", "Bitcoin"
    symbol: str          # e.g. "ETH", "BTC"
    derivation_path: str  # e.g. "m/44'/60'/0'/0/0"
    private_key_hex: Optional[str] = None  # Only if derived from mnemonic


# --- Chain ID to Bip44Coins mapping ---
_COIN_MAP: dict[str, Bip44Coins] = {
    "bitcoin": Bip44Coins.BITCOIN,
    "ethereum": Bip44Coins.ETHEREUM,
    "bnb smart chain": Bip44Coins.ETHEREUM,  # Same key derivation
    "polygon": Bip44Coins.ETHEREUM,           # Same key derivation
    "solana": Bip44Coins.SOLANA,
}


def is_valid_mnemonic(mnemonic: str) -> bool:
    """Check if a string is a valid BIP-39 mnemonic."""
    try:
        return Bip39MnemonicValidator().IsValid(mnemonic.strip())
    except Exception:
        return False


def detect_input_type(target: str) -> str:
    """Detect whether input is a mnemonic, private key, or address.

    Returns: 'mnemonic', 'private_key', 'btc_address', 'evm_address',
             'sol_address', or 'unknown'
    """
    target = target.strip()

    # Mnemonic: 12, 15, 18, 21, or 24 words
    words = target.split()
    if len(words) in (12, 15, 18, 21, 24) and all(w.isalpha() for w in words):
        if is_valid_mnemonic(target):
            return "mnemonic"

    # BTC address: starts with 1, 3, or bc1
    if re.match(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$", target):
        return "btc_address"

    # EVM address: 0x + 40 hex chars
    if re.match(r"^0x[0-9a-fA-F]{40}$", target):
        return "evm_address"

    # SOL address: base58, 32-44 chars
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", target):
        return "sol_address"

    # Private key: 64 hex chars (with or without 0x)
    clean = target.removeprefix("0x")
    if re.match(r"^[0-9a-fA-F]{64}$", clean):
        return "private_key"

    return "unknown"


def derive_from_mnemonic(
    mnemonic: str,
    chains: Optional[list[ChainConfig]] = None,
    account: int = 0,
    count: int = 1,
) -> list[DerivedAddress]:
    """Derive addresses from a BIP-39 mnemonic for multiple chains.

    Args:
        mnemonic: Valid BIP-39 mnemonic phrase.
        chains: List of chains to derive for. Defaults to all supported chains.
        account: Account index (BIP-44 level 2).
        count: Number of address indices to derive per chain/path.

    Returns:
        List of DerivedAddress objects.
    """
    if not is_valid_mnemonic(mnemonic):
        raise ValueError("Invalid BIP-39 mnemonic")

    if chains is None:
        chains = list(ALL_CHAINS)

    seed_bytes = Bip39SeedGenerator(mnemonic.strip()).Generate()
    results: list[DerivedAddress] = []

    for chain in chains:
        coin_enum = _COIN_MAP.get(chain.name.lower())
        if coin_enum is None:
            continue

        for path in chain.derivation_paths:
            for addr_idx in range(count):
                try:
                    ctx = Bip44.FromSeed(seed_bytes, coin_enum)
                    # Parse derivation path to navigate hierarchy
                    parts = _parse_derivation_path(path, account, addr_idx)
                    node = ctx
                    for part in parts:
                        if part == "purpose":
                            node = node.Purpose()
                        elif part == "coin":
                            node = node.Coin()
                        elif part == "account":
                            node = node.Account(account)
                        elif part == "change":
                            node = node.Change(Bip44Changes.CHAIN_EXT)
                        elif part == "address":
                            node = node.AddressIndex(addr_idx)

                    address = node.PublicKey().ToAddress()
                    privkey = node.PrivateKey().Raw().ToHex()

                    results.append(DerivedAddress(
                        address=address,
                        chain=chain.name,
                        symbol=chain.symbol,
                        derivation_path=path,
                        private_key_hex=privkey,
                    ))
                except Exception:
                    continue

    return results


def derive_from_privatekey(
    key_hex: str,
    chain: Optional[ChainConfig] = None,
) -> DerivedAddress:
    """Derive address from a raw private key.

    Args:
        key_hex: Hex-encoded private key (64 chars, with or without 0x prefix).
        chain: Target chain. Defaults to Ethereum.

    Returns:
        DerivedAddress for the key.
    """
    from eth_account import Account

    clean_key = key_hex.strip().removeprefix("0x")
    if not re.match(r"^[0-9a-fA-F]{64}$", clean_key):
        raise ValueError("Invalid private key format (expected 64 hex chars)")

    if chain is None:
        chain = ETHEREUM

    account = Account.from_key(bytes.fromhex(clean_key))
    return DerivedAddress(
        address=account.address,
        chain=chain.name,
        symbol=chain.symbol,
        derivation_path="direct",
        private_key_hex=clean_key,
    )


def _parse_derivation_path(path: str, account: int, address_idx: int) -> list[str]:
    """Parse a BIP-44 derivation path string into navigation steps.

    Returns a list of step names like ['purpose', 'coin', 'account', 'change', 'address'].
    """
    # Standard BIP-44: m / purpose' / coin_type' / account' / change / address_index
    return ["purpose", "coin", "account", "change", "address"]
