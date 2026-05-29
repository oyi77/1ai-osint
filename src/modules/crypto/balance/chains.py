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
    "https://rpc.ankr.com/eth",
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
]
BSC_RPCS = [
    "https://bsc-dataseed.binance.org",
    "https://bsc-dataseed1.binance.org",
    "https://rpc.ankr.com/bsc",
    "https://bsc-rpc.publicnode.com",
]
POLYGON_RPCS = [
    "https://rpc.ankr.com/polygon",
    "https://polygon-bor-rpc.publicnode.com",
    "https://1rpc.io/matic",
]
SOL_RPCS = [
    "https://solana-rpc.publicnode.com",
]


class ChainType(str, Enum):
    """Blockchain type — determines RPC protocol."""
    EVM = "evm"          # ETH, BSC, Polygon — web3 JSON-RPC
    BITCOIN = "bitcoin"  # BTC — REST API
    SOLANA = "solana"    # SOL — JSON-RPC


@dataclass
class ChainConfig:
    """Configuration for a single blockchain."""
    name: str
    symbol: str
    chain_type: ChainType
    coin_id: str                     # CoinGecko API ID
    rpc_url: Optional[str] = None    # For EVM/Solana
    api_url: Optional[str] = None    # For BTC (blockstream.info)
    decimals: int = 18
    bip44_coin_type: int = 60        # BIP-44 coin type
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
    derivation_paths=["m/44'/60'/0'/0/0"],
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
        "m/44'/0'/0'/0/0",   # Legacy P2PKH
        "m/49'/0'/0'/0/0",   # SegWit P2SH-P2WPKH
        "m/84'/0'/0'/0/0",   # Native SegWit Bech32
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
    derivation_paths=["m/44'/501'/0'/0'"],
)

# All supported chains
ALL_CHAINS: list[ChainConfig] = [ETHEREUM, BSC, POLYGON, BITCOIN, SOLANA]

# Map for quick lookup by name
CHAIN_MAP: dict[str, ChainConfig] = {c.name.lower(): c for c in ALL_CHAINS}
CHAIN_MAP.update({c.symbol.lower(): c for c in ALL_CHAINS})
