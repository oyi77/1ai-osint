"""Wallet provider profiles — derivation paths and generation patterns.

Each provider (Binance/Trust Wallet, OKX, Gate.io, BTGET) uses standard
BIP-39/BIP-44 but with different derivation paths and address counts.

This module defines provider-specific profiles for targeted scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProviderProfile:
    """A wallet provider's derivation configuration."""
    name: str
    # Chains and their derivation paths
    evm_paths: list[str] = field(default_factory=lambda: ["m/44'/60'/0'/0/0"])
    btc_paths: list[str] = field(default_factory=lambda: [
        "m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0",
    ])
    sol_paths: list[str] = field(default_factory=lambda: ["m/44'/501'/0'/0'"])
    # Number of address indices to check per path
    address_count: int = 5
    # Mnemonic length (12 or 24 words)
    mnemonic_words: int = 12


# --- Provider Profiles ---

BINANCE = ProviderProfile(
    name="Binance (Trust Wallet)",
    evm_paths=[
        "m/44'/60'/0'/0/0",    # Standard ETH
        "m/44'/60'/0'/0/1",    # Second address
        "m/44'/60'/1'/0/0",    # Account 1
        "m/44'/714'/0'/0/0",   # BNB Chain native (BIP-44 coin type 714)
    ],
    btc_paths=[
        "m/44'/0'/0'/0/0",     # Legacy
        "m/49'/0'/0'/0/0",     # SegWit
        "m/84'/0'/0'/0/0",     # Native SegWit (default in Trust Wallet)
        "m/86'/0'/0'/0/0",     # Taproot
    ],
    sol_paths=["m/44'/501'/0'/0'"],
    address_count=10,
    mnemonic_words=12,
)

OKX = ProviderProfile(
    name="OKX Wallet",
    evm_paths=[
        "m/44'/60'/0'/0/0",    # Standard
        "m/44'/60'/0'/0/1",    # Second address
        "m/44'/60'/1'/0/0",    # Account 1
    ],
    btc_paths=[
        "m/44'/0'/0'/0/0",     # Legacy
        "m/49'/0'/0'/0/0",     # SegWit
        "m/84'/0'/0'/0/0",     # Native SegWit
        "m/86'/0'/0'/0/0",     # Taproot (OKX default for BTC)
    ],
    sol_paths=[
        "m/44'/501'/0'/0'",    # Standard
        "m/44'/501'/0'/0'/0'", # OKX alternative
    ],
    address_count=5,
    mnemonic_words=12,
)

GATEIO = ProviderProfile(
    name="Gate.io Wallet",
    evm_paths=[
        "m/44'/60'/0'/0/0",    # Standard
        "m/44'/60'/0'/0/1",    # Second address
    ],
    btc_paths=[
        "m/44'/0'/0'/0/0",     # Legacy
        "m/49'/0'/0'/0/0",     # SegWit
        "m/84'/0'/0'/0/0",     # Native SegWit
    ],
    sol_paths=["m/44'/501'/0'/0'"],
    address_count=3,
    mnemonic_words=12,
)

BTGET = ProviderProfile(
    name="BTGET Wallet",
    evm_paths=[
        "m/44'/60'/0'/0/0",    # Standard
    ],
    btc_paths=[
        "m/44'/0'/0'/0/0",     # Legacy
        "m/49'/0'/0'/0/0",     # SegWit
        "m/84'/0'/0'/0/0",     # Native SegWit
    ],
    sol_paths=["m/44'/501'/0'/0'"],
    address_count=3,
    mnemonic_words=12,
)

# Generic profile (covers most wallets)
GENERIC = ProviderProfile(
    name="Generic (all standard paths)",
    evm_paths=[
        "m/44'/60'/0'/0/0",
        "m/44'/60'/0'/0/1",
        "m/44'/60'/1'/0/0",
    ],
    btc_paths=[
        "m/44'/0'/0'/0/0",
        "m/49'/0'/0'/0/0",
        "m/84'/0'/0'/0/0",
        "m/86'/0'/0'/0/0",
    ],
    sol_paths=[
        "m/44'/501'/0'/0'",
    ],
    address_count=5,
    mnemonic_words=12,
)

# All providers for comprehensive scanning
ALL_PROVIDERS: list[ProviderProfile] = [BINANCE, OKX, GATEIO, BTGET, GENERIC]
