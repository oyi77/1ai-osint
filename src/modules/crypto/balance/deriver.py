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


# --- Base58 encoding/decoding for Solana keys ---
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(s: str) -> bytes:
    """Decode a base58 string to bytes."""
    n = 0
    for ch in s.encode():
        n = n * 58 + _BASE58_ALPHABET.index(ch)
    result = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # Add leading zero bytes for leading '1' chars
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + result


def _base58_encode(b: bytes) -> str:
    """Encode bytes to base58 string."""
    n = int.from_bytes(b, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_BASE58_ALPHABET[r:r + 1].decode())
    # Add leading '1' for leading zero bytes
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + "".join(reversed(result))


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

    # BTC address: starts with 1, 3, or bc1 (check BEFORE base58 private key)
    if re.match(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$", target):
        return "btc_address"

    # EVM address: 0x + 40 hex chars
    if re.match(r"^0x[0-9a-fA-F]{40}$", target):
        return "evm_address"

    # Private key: 64 hex chars (with or without 0x)
    clean = target.removeprefix("0x")
    if re.match(r"^[0-9a-fA-F]{64}$", clean):
        return "private_key"

    # Solana private key: base58, 87-88 chars (encodes 64 bytes)
    # Must NOT start with 1,3,5 (BTC WIF prefix) or start with 0x
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{87,88}$", target) and not target.startswith(("1", "3", "5")):
        return "private_key"

    # SOL address: base58, 32-44 chars (checked LAST — overlaps with other base58 formats)
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", target):
        return "sol_address"

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

    Supports hex keys (64 chars, EVM/BTC) and base58 keys (87-88 chars, SOL).

    Args:
        key_hex: Private key (hex or base58 encoded).
        chain: Target chain. Defaults to Ethereum.

    Returns:
        DerivedAddress for the key.
    """
    clean_key = key_hex.strip().removeprefix("0x")

    # Detect key format
    is_hex = re.match(r"^[0-9a-fA-F]{64}$", clean_key)
    is_base58 = re.match(r"^[1-9A-HJ-NP-Za-km-z]{87,88}$", key_hex.strip())

    if is_hex:
        # EVM-compatible hex key
        from eth_account import Account
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
    elif is_base58:
        # Solana base58 key
        import base64
        try:
            decoded = _base58_decode(key_hex.strip())
            if len(decoded) == 64:
                # Derive Solana public key from private key
                # ed25519: first 32 bytes = secret, last 32 bytes = public key
                public_key_bytes = decoded[32:64]
                address = _base58_encode(public_key_bytes)
                sol_chain = SOLANA if chain is None else chain
                return DerivedAddress(
                    address=address,
                    chain=sol_chain.name,
                    symbol=sol_chain.symbol,
                    derivation_path="direct",
                    private_key_hex=decoded.hex(),
                )
        except Exception:
            pass

    raise ValueError("Invalid private key format (expected 64 hex chars or 88 base58 chars)")


def _parse_derivation_path(path: str, account: int, address_idx: int) -> list[str]:
    """Parse a BIP-44 derivation path string into navigation steps.

    Returns a list of step names like ['purpose', 'coin', 'account', 'change', 'address'].
    """
    # Standard BIP-44: m / purpose' / coin_type' / account' / change / address_index
    return ["purpose", "coin", "account", "change", "address"]
