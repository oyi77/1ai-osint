"""Chain configuration for multi-chain balance checking."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# Fallback endpoint lists for rotation (avoids rate limits)
BTC_APIS = [
    "https://blockstream.info/api",
    "https://mempool.space/api",
]
ETH_RPCS = [
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
    "https://cloudflare-eth.com",
]
BSC_RPCS = [
    "https://bsc-dataseed.binance.org",
    "https://bsc-dataseed1.binance.org",
    "https://rpc.ankr.com/bsc",
    "https://bsc-rpc.publicnode.com",
]
POLYGON_RPCS = [
    "https://polygon-bor-rpc.publicnode.com",
    "https://1rpc.io/matic",
    "https://polygon.llamarpc.com",
]
ARBITRUM_RPCS = [
    "https://arb1.arbitrum.io/rpc",
    "https://arbitrum.llamarpc.com",
    "https://arbitrum-one-rpc.publicnode.com",
]
OPTIMISM_RPCS = [
    "https://mainnet.optimism.io",
    "https://optimism.llamarpc.com",
    "https://optimism-rpc.publicnode.com",
]
BASE_RPCS = [
    "https://mainnet.base.org",
    "https://base.llamarpc.com",
    "https://base-rpc.publicnode.com",
]
AVALANCHE_RPCS = [
    "https://api.avax.network/ext/bc/C/rpc",
    "https://avalanche-c-chain-rpc.publicnode.com",
    "https://avax.meowrpc.com",
]
FANTOM_RPCS = [
    "https://rpc.ftm.tools",
    "https://fantom-rpc.publicnode.com",
    "https://rpcapi.fantom.network",
]
SOL_RPCS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
]


class ChainType(str, Enum):
    """Blockchain type — determines RPC protocol."""

    EVM = "evm"  # ETH, BSC, Polygon — web3 JSON-RPC
    BITCOIN = "bitcoin"  # BTC — REST API
    SOLANA = "solana"  # SOL — JSON-RPC


@dataclass
class ChainConfig:
    """Configuration for a single blockchain."""

    name: str
    symbol: str
    chain_type: ChainType
    coin_id: str  # CoinGecko API ID
    rpc_url: Optional[str] = None  # For EVM/Solana
    api_url: Optional[str] = None  # For BTC (blockstream.info)
    decimals: int = 18
    bip44_coin_type: int = 60  # BIP-44 coin type
    derivation_paths: list[str] = field(default_factory=lambda: ["m/44'/60'/0'/0/0"])


# --- Chain Definitions ---

ETHEREUM = ChainConfig(
    name="Ethereum",
    symbol="ETH",
    chain_type=ChainType.EVM,
    coin_id="ethereum",
    rpc_url="https://ethereum-rpc.publicnode.com",
    decimals=18,
    bip44_coin_type=60,
    derivation_paths=[
        "m/44'/60'/0'/0/0",  # Standard BIP-44 (MetaMask, Trust, OKX, Gate.io)
        "m/44'/60'/0'/0/1",  # Second address (some wallets auto-generate)
        "m/44'/60'/1'/0/0",  # Account 1 (Binance sometimes uses)
    ],
)

BSC = ChainConfig(
    name="BNB Smart Chain",
    symbol="BNB",
    chain_type=ChainType.EVM,
    coin_id="binancecoin",
    rpc_url="https://bsc-dataseed.binance.org",
    decimals=18,
    bip44_coin_type=60,  # Same derivation as ETH
    derivation_paths=["m/44'/60'/0'/0/0"],
)

POLYGON = ChainConfig(
    name="Polygon",
    symbol="MATIC",
    chain_type=ChainType.EVM,
    coin_id="matic-network",
    rpc_url="https://polygon-bor-rpc.publicnode.com",
    decimals=18,
    bip44_coin_type=60,  # Same derivation as ETH
    derivation_paths=["m/44'/60'/0'/0/0"],
)

BITCOIN = ChainConfig(
    name="Bitcoin",
    symbol="BTC",
    chain_type=ChainType.BITCOIN,
    coin_id="bitcoin",
    api_url="https://mempool.space/api",
    decimals=8,
    bip44_coin_type=0,
    derivation_paths=[
        "m/44'/0'/0'/0/0",  # Legacy P2PKH
        "m/44'/0'/0'/0/1",  # Legacy second address
        "m/49'/0'/0'/0/0",  # SegWit P2SH-P2WPKH
        "m/49'/0'/0'/0/1",  # SegWit second address
        "m/84'/0'/0'/0/0",  # Native SegWit Bech32
        "m/84'/0'/0'/0/1",  # Native SegWit second address
        "m/86'/0'/0'/0/0",  # Taproot (BIP-86, used by OKX/Trust)
    ],
)

SOLANA = ChainConfig(
    name="Solana",
    symbol="SOL",
    chain_type=ChainType.SOLANA,
    coin_id="solana",
    rpc_url="https://api.mainnet-beta.solana.com",
    decimals=9,
    bip44_coin_type=501,
    derivation_paths=[
        "m/44'/501'/0'/0'",  # Standard (Phantom, Solflare)
        "m/44'/501'/0'/0'/0'",  # Alternative (some OKX versions)
    ],
)

# --- Additional EVM Chains (same private key as ETH) ---

ARBITRUM = ChainConfig(
    name="Arbitrum",
    symbol="ETH",
    chain_type=ChainType.EVM,
    coin_id="ethereum",
    rpc_url="https://arb1.arbitrum.io/rpc",
    decimals=18,
    bip44_coin_type=60,
    derivation_paths=["m/44'/60'/0'/0/0"],
)

OPTIMISM = ChainConfig(
    name="Optimism",
    symbol="ETH",
    chain_type=ChainType.EVM,
    coin_id="ethereum",
    rpc_url="https://mainnet.optimism.io",
    decimals=18,
    bip44_coin_type=60,
    derivation_paths=["m/44'/60'/0'/0/0"],
)

BASE = ChainConfig(
    name="Base",
    symbol="ETH",
    chain_type=ChainType.EVM,
    coin_id="ethereum",
    rpc_url="https://mainnet.base.org",
    decimals=18,
    bip44_coin_type=60,
    derivation_paths=["m/44'/60'/0'/0/0"],
)

AVALANCHE = ChainConfig(
    name="Avalanche",
    symbol="AVAX",
    chain_type=ChainType.EVM,
    coin_id="avalanche-2",
    rpc_url="https://api.avax.network/ext/bc/C/rpc",
    decimals=18,
    bip44_coin_type=60,
    derivation_paths=["m/44'/60'/0'/0/0"],
)

FANTOM = ChainConfig(
    name="Fantom",
    symbol="FTM",
    chain_type=ChainType.EVM,
    coin_id="fantom",
    rpc_url="https://rpc.ftm.tools",
    decimals=18,
    bip44_coin_type=60,
    derivation_paths=["m/44'/60'/0'/0/0"],
)

# All supported chains
ALL_CHAINS: list[ChainConfig] = [
    ETHEREUM, BSC, POLYGON, ARBITRUM, OPTIMISM, BASE, AVALANCHE, FANTOM,
    BITCOIN, SOLANA,
]

# Map for quick lookup by name
CHAIN_MAP: dict[str, ChainConfig] = {c.name.lower(): c for c in ALL_CHAINS}
CHAIN_MAP.update({c.symbol.lower(): c for c in ALL_CHAINS})


def chain_by_name(name: str) -> Optional[ChainConfig]:
    """Look up a chain by name or symbol (case-insensitive)."""
    return CHAIN_MAP.get(name.lower())
