"""Address derivation from mnemonic phrases and private keys.

Supports BTC (BIP-44/49/84), ETH, BSC, Polygon, and SOL.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)

# Import BIP-49/84/86 classes if available (for SegWit/Taproot derivation)
try:
    from bip_utils import Bip49, Bip84, Bip86

    _HAS_BIP84 = True
except ImportError:
    _HAS_BIP84 = False

from src.modules.crypto.balance.chains import (
    ALL_CHAINS,
    ETHEREUM,
    SOLANA,
    ChainConfig,
    ChainType,
)
from src.modules.crypto.balance.provider_profiles import ProviderProfile

logger = logging.getLogger(__name__)

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
        result.append(_BASE58_ALPHABET[r : r + 1].decode())
    # Add leading '1' for leading zero bytes
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + "".join(reversed(result))


@dataclass
class DerivedAddress:
    """A derived wallet address with metadata."""

    address: str
    chain: str  # e.g. "Ethereum", "Bitcoin"
    symbol: str  # e.g. "ETH", "BTC"
    derivation_path: str  # e.g. "m/44'/60'/0'/0/0"
    private_key_hex: str | None = None  # Only if derived from mnemonic


# --- Chain ID to Bip44Coins mapping ---
_COIN_MAP: dict[str, Bip44Coins] = {
    "bitcoin": Bip44Coins.BITCOIN,
    "ethereum": Bip44Coins.ETHEREUM,
    "bnb smart chain": Bip44Coins.ETHEREUM,  # Same key derivation
    "polygon": Bip44Coins.ETHEREUM,  # Same key derivation
    "arbitrum": Bip44Coins.ETHEREUM,  # Same key derivation
    "optimism": Bip44Coins.ETHEREUM,  # Same key derivation
    "base": Bip44Coins.ETHEREUM,  # Same key derivation
    "avalanche": Bip44Coins.ETHEREUM,  # Same key derivation
    "fantom": Bip44Coins.ETHEREUM,  # Same key derivation
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
    chains: list[ChainConfig] | None = None,
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

        # For BTC, also derive change addresses (internal); for others, external only
        changes = [Bip44Changes.CHAIN_EXT]
        if chain.chain_type == ChainType.BITCOIN:
            changes.append(Bip44Changes.CHAIN_INT)

        for path in chain.derivation_paths:
            for change in changes:
                for addr_idx in range(count):
                    try:
                        # Select the correct BIP class based on the path's purpose level
                        purpose = _get_purpose_from_path(path)
                        if purpose == 49 and _HAS_BIP84:
                            ctx = Bip49.FromSeed(seed_bytes, coin_enum)
                        elif purpose == 84 and _HAS_BIP84:
                            ctx = Bip84.FromSeed(seed_bytes, coin_enum)
                        elif purpose == 86 and _HAS_BIP84:
                            ctx = Bip86.FromSeed(seed_bytes, coin_enum)
                        else:
                            ctx = Bip44.FromSeed(seed_bytes, coin_enum)

                        node = ctx.Purpose().Coin()
                        node = node.Account(account)
                        node = node.Change(change)
                        node = node.AddressIndex(addr_idx)

                        address = node.PublicKey().ToAddress()
                        privkey = node.PrivateKey().Raw().ToHex()

                        # Mark change addresses in the path
                        path_label = path
                        if change == Bip44Changes.CHAIN_INT:
                            path_label = path + " (change)"

                        results.append(
                            DerivedAddress(
                                address=address,
                                chain=chain.name,
                                symbol=chain.symbol,
                                derivation_path=path_label,
                                private_key_hex=privkey,
                            )
                        )
                    except Exception:
                        continue

    return results


def derive_from_mnemonic_provider(
    mnemonic: str,
    provider: ProviderProfile,
    chains: list[ChainConfig] | None = None,
) -> list[DerivedAddress]:
    """Derive addresses using a provider-specific profile.

    Uses provider-specific derivation paths and address counts instead of
    the chain defaults. This allows targeting wallets from specific providers
    (Binance, OKX, Gate.io, BTGET).

    Args:
        mnemonic: Valid BIP-39 mnemonic phrase.
        provider: ProviderProfile with derivation config.
        chains: Chain configs (for chain metadata like name/symbol).

    Returns:
        List of DerivedAddress objects.

    """
    if not is_valid_mnemonic(mnemonic):
        raise ValueError("Invalid BIP-39 mnemonic")

    if chains is None:
        chains = list(ALL_CHAINS)

    chain_map = {c.name.lower(): c for c in chains}

    seed_bytes = Bip39SeedGenerator(mnemonic.strip()).Generate()
    results: list[DerivedAddress] = []

    # EVM paths (ETH, BSC, Polygon share same derivation)
    evm_chains = [c for c in chains if c.chain_type.value == "evm"]
    for path in provider.evm_paths:
        for addr_idx in range(provider.address_count):
            for chain in evm_chains:
                try:
                    coin_enum = _COIN_MAP.get(chain.name.lower())
                    if coin_enum is None:
                        continue
                    purpose = _get_purpose_from_path(path)
                    if purpose == 49 and _HAS_BIP84:
                        ctx = Bip49.FromSeed(seed_bytes, coin_enum)
                    elif purpose == 84 and _HAS_BIP84:
                        ctx = Bip84.FromSeed(seed_bytes, coin_enum)
                    elif purpose == 86 and _HAS_BIP84:
                        ctx = Bip86.FromSeed(seed_bytes, coin_enum)
                    else:
                        ctx = Bip44.FromSeed(seed_bytes, coin_enum)
                    node = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(addr_idx)
                    address = node.PublicKey().ToAddress()
                    privkey = node.PrivateKey().Raw().ToHex()
                    results.append(
                        DerivedAddress(
                            address=address,
                            chain=chain.name,
                            symbol=chain.symbol,
                            derivation_path=path,
                            private_key_hex=privkey,
                        )
                    )
                except Exception:
                    continue

    # BTC paths
    btc_chain = chain_map.get("bitcoin")
    if btc_chain:
        for path in provider.btc_paths:
            for addr_idx in range(provider.address_count):
                try:
                    purpose = _get_purpose_from_path(path)
                    if purpose == 49 and _HAS_BIP84:
                        ctx = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
                    elif purpose == 84 and _HAS_BIP84:
                        ctx = Bip84.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
                    elif purpose == 86 and _HAS_BIP84:
                        ctx = Bip86.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
                    else:
                        ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
                    node = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(addr_idx)
                    address = node.PublicKey().ToAddress()
                    privkey = node.PrivateKey().Raw().ToHex()
                    results.append(
                        DerivedAddress(
                            address=address,
                            chain="Bitcoin",
                            symbol="BTC",
                            derivation_path=path,
                            private_key_hex=privkey,
                        )
                    )
                except Exception:
                    continue

    # SOL paths
    sol_chain = chain_map.get("solana")
    if sol_chain:
        for path in provider.sol_paths:
            for addr_idx in range(min(provider.address_count, 3)):
                try:
                    ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
                    node = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(addr_idx)
                    address = node.PublicKey().ToAddress()
                    privkey = node.PrivateKey().Raw().ToHex()
                    results.append(
                        DerivedAddress(
                            address=address,
                            chain="Solana",
                            symbol="SOL",
                            derivation_path=path,
                            private_key_hex=privkey,
                        )
                    )
                except Exception:
                    continue

    return results


def derive_from_privatekey(
    key_hex: str,
    chain: ChainConfig | None = None,
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
            logger.debug("Failed to decode base58 key", exc_info=True)

    raise ValueError("Invalid private key format (expected 64 hex chars or 88 base58 chars)")


def _get_purpose_from_path(path: str) -> int:
    """Extract the BIP purpose number from a derivation path string.

    Args:
        path: Derivation path like "m/44'/60'/0'/0/0" or "m/84'/0'/0'/0/0".

    Returns:
        Purpose number (44, 49, 84, or 86). Defaults to 44 if unrecognized.

    """
    try:
        parts = path.replace("m/", "").split("/")
        if parts:
            return int(parts[0].rstrip("'h"))
    except (ValueError, IndexError):
        pass
    return 44


def derive_with_raw_path(
    mnemonic: str,
    derivation_path: str,
    chain_name: str,
    chain_symbol: str,
    coin_enum,
    address_idx: int = 0,
) -> DerivedAddress | None:
    """Derive a single address using raw BIP-32 path derivation.

    This bypasses the BIP-44 library's path restriction and allows
    any valid BIP-32 path (BIP-49, BIP-84, BIP-86, etc.).

    Args:
        mnemonic: Valid BIP-39 mnemonic.
        derivation_path: Full path like "m/84'/0'/0'/0/0".
        chain_name: Display name (e.g., "Bitcoin").
        chain_symbol: Symbol (e.g., "BTC").
        coin_enum: Bip44Coins enum value.
        address_idx: Address index to use (replaces last path component).

    Returns:
        DerivedAddress or None on failure.

    """
    try:
        from bip_utils import Bip32Secp256k1
    except ImportError:
        return None

    try:
        seed_bytes = Bip39SeedGenerator(mnemonic.strip()).Generate()
        # Parse path and replace last component with address_idx
        parts = derivation_path.strip("m/").split("/")
        if parts:
            parts[-1] = str(address_idx)

        # Build full path

        bip32_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
        for part in parts:
            hardened = part.endswith("'")
            idx_str = part.rstrip("'")
            idx = int(idx_str)
            bip32_ctx = bip32_ctx.ChildKey(idx + 0x80000000 if hardened else idx)

        address = bip32_ctx.PublicKey().ToAddress()
        privkey = bip32_ctx.PrivateKey().Raw().ToHex()

        return DerivedAddress(
            address=address,
            chain=chain_name,
            symbol=chain_symbol,
            derivation_path=derivation_path,
            private_key_hex=privkey,
        )
    except Exception:
        return None
