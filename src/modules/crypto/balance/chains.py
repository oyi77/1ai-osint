"""Chain configuration for multi-chain balance checking."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ChainType(str, Enum):
    """Blockchain type — determines RPC protocol."""

    EVM = "evm"  # ETH, BSC, Polygon — web3 JSON-RPC
    BITCOIN = "bitcoin"  # BTC — REST API
    SOLANA = "solana"  # SOL — JSON-RPC


@dataclass
class TokenContract:
    """ERC-20/BEP-20 token contract for balance checking."""

    symbol: str
    address: str  # Contract address (checksummed)
    decimals: int


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
    tokens: list[TokenContract] = field(
        default_factory=list
    )  # Top ERC-20 tokens to check


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
    tokens=[
        TokenContract("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
        TokenContract("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
        TokenContract("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18),
        TokenContract("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18),
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
    tokens=[
        TokenContract("USDT", "0x55d398326f99059fF775485246999027B3197955", 18),
        TokenContract("USDC", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18),
        TokenContract("BUSD", "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", 18),
    ],
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
    tokens=[
        TokenContract("USDT", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6),
        TokenContract("USDC", "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 6),
    ],
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
    tokens=[
        TokenContract("USDT", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
        TokenContract("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
    ],
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
    tokens=[
        TokenContract("USDT", "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", 6),
        TokenContract("USDC", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 6),
    ],
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
    tokens=[
        TokenContract("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
    ],
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
    tokens=[
        TokenContract("USDT", "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", 6),
        TokenContract("USDC", "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6),
    ],
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
    tokens=[
        TokenContract("USDT", "0x049d68029688eAbF473097a2fC38ef61633A3C7A", 6),
        TokenContract("USDC", "0x04068DA6C83AFCFA0e13ba15A6696662335D5B75", 6),
    ],
)

# All supported chains
ALL_CHAINS: list[ChainConfig] = [
    ETHEREUM,
    BSC,
    POLYGON,
    ARBITRUM,
    OPTIMISM,
    BASE,
    AVALANCHE,
    FANTOM,
    BITCOIN,
    SOLANA,
]

# Map for quick lookup by name
CHAIN_MAP: dict[str, ChainConfig] = {c.name.lower(): c for c in ALL_CHAINS}
CHAIN_MAP.update({c.symbol.lower(): c for c in ALL_CHAINS})


def chain_by_name(name: str) -> Optional[ChainConfig]:
    """Look up a chain by name or symbol (case-insensitive)."""
    return CHAIN_MAP.get(name.lower())
