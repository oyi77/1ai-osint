"""Crypto Balance Checker — derive addresses and check on-chain balances.

Supports BTC, ETH, BSC, Polygon, and SOL. Accepts mnemonic phrases,
private keys, or raw addresses as input.

Operates in five scan modes:
- "random": generate random mnemonics and check balances (RandomScanner)
- "targeted": derive and check known mnemonics / account ranges (targeted_search)
- "leak": scan GitHub/Pastebin for leaked mnemonics and verify balances
- "leak_key": scan GitHub/Pastebin for leaked private keys (hex, base58, WIF)
- "smart": AI word-frequency biased mnemonic generation and verification
"""

from __future__ import annotations

from src.modules.crypto.balance.chains import ALL_CHAINS, CHAIN_MAP, ChainConfig
from src.modules.crypto.balance.checker import (
    BalanceResult,
    apply_usd_prices,
    check_balance,
    get_usd_prices,
)
from src.modules.crypto.balance.deriver import (
    DerivedAddress,
    derive_from_mnemonic,
    derive_from_privatekey,
    detect_input_type,
    is_valid_mnemonic,
)
from src.modules.crypto.balance.targeted_search import (
    AccountRangeScan,
    FilteredRandomScan,
    TargetedScanResult,
    targeted_scan_to_scanresult,
)
from src.modules.crypto.balance.tool import CryptoBalanceTool

__all__ = [
    "CryptoBalanceTool",
    # Re-exports for convenience
    "DerivedAddress",
    "derive_from_mnemonic",
    "derive_from_privatekey",
    "detect_input_type",
    "is_valid_mnemonic",
    "BalanceResult",
    "apply_usd_prices",
    "check_balance",
    "get_usd_prices",
    "AccountRangeScan",
    "FilteredRandomScan",
    "TargetedScanResult",
    "targeted_scan_to_scanresult",
    "ALL_CHAINS",
    "CHAIN_MAP",
    "ChainConfig",
]
