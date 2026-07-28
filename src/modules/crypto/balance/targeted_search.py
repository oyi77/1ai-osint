"""Targeted search strategies for crypto balance scanning.

Provides three targeted approaches:
- KnownMnemonicLookup: derive and check a specific mnemonic across chains
- AccountRangeScan: scan accounts 0-N for a given seed
- FilteredRandomScan: random mnemonic scan with balance/path filters
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.core.models import Finding, ScanResult, Severity
from src.modules.crypto.balance.chains import ALL_CHAINS, ChainConfig
from src.modules.crypto.balance.checker import (
    BalanceResult,
    apply_usd_prices,
    check_balance,
    get_usd_prices,
)
from src.modules.crypto.balance.deriver import (
    DerivedAddress,
    derive_from_mnemonic,
    is_valid_mnemonic,
)

logger = logging.getLogger(__name__)


@dataclass
class TargetedScanResult:
    """Result container for targeted search operations."""

    scan_id: str
    mode: str
    findings: list[Finding] = field(default_factory=list)
    addresses_checked: int = 0
    chains_checked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    has_hits: bool = False


class KnownMnemonicLookup:
    """Derive and check balances for a specific known mnemonic.

    Given a mnemonic phrase, derives addresses across all requested chains
    and checks their on-chain balances.

    Example::

        lookup = KnownMnemonicLookup(mnemonic="abandon ...", chains=[ETHEREUM, BITCOIN])
        result = await lookup.execute()
    """

    def __init__(
        self,
        mnemonic: str,
        chains: list[ChainConfig] | None = None,
        account_range: tuple[int, int] = (0, 1),
    ):
        self.mnemonic = mnemonic.strip()
        if not is_valid_mnemonic(self.mnemonic):
            raise ValueError("Invalid BIP-39 mnemonic")
        self.chains = chains or list(ALL_CHAINS)
        self.account_start, self.account_end = account_range

    async def execute(self, scan_id: str = "") -> TargetedScanResult:
        """Execute the known mnemonic lookup.

        Returns:
            TargetedScanResult with findings for each address with balance > 0.

        """
        if not is_valid_mnemonic(self.mnemonic):
            return TargetedScanResult(
                scan_id=scan_id,
                mode="known_mnemonic",
                errors=["Invalid BIP-39 mnemonic"],
            )

        findings: list[Finding] = []
        errors: list[str] = []
        addresses: list[DerivedAddress] = []

        # Derive addresses for each account index in range
        for account_idx in range(self.account_start, self.account_end):
            try:
                addrs = derive_from_mnemonic(
                    self.mnemonic,
                    chains=self.chains,
                    account=account_idx,
                    count=1,
                )
                addresses.extend(addrs)
            except Exception as e:
                errors.append(f"Account {account_idx}: {e}")

        if not addresses:
            return TargetedScanResult(
                scan_id=scan_id,
                mode="known_mnemonic",
                errors=errors or ["No addresses derived"],
            )

        # Check balances concurrently
        balance_tasks = [
            check_balance(
                addr.address,
                chain_by_name(addr.chain, self.chains) or self.chains[0],
                addr.derivation_path,
            )
            for addr in addresses
        ]
        balance_results = await asyncio.gather(*balance_tasks, return_exceptions=True)

        # Fetch USD prices
        coin_ids = list({c.coin_id for c in self.chains})
        prices = await get_usd_prices(coin_ids)

        # Build findings
        valid_results: list[BalanceResult] = []
        for i, result in enumerate(balance_results):
            if isinstance(result, Exception):
                errors.append(f"{addresses[i].chain}: {result}")
                continue
            valid_results.append(result)  # type: ignore[arg-type]

        apply_usd_prices(valid_results, prices)

        for result in valid_results:
            severity = Severity.INFO
            if result.balance > 0:
                severity = Severity.HIGH
            if result.usd_value > 1000:
                severity = Severity.CRITICAL

            title = f"{result.chain}: {result.balance:.8f} {result.symbol}"
            if result.usd_price > 0:
                title += f" (~${result.usd_value:,.2f})"

            findings.append(
                Finding(
                    id=f"km-{scan_id}-{len(findings)}",
                    module="crypto_balance",
                    title=title,
                    description=f"Known mnemonic lookup for {result.address} on {result.chain}",
                    severity=severity,
                    confidence=1.0,
                    tags=[
                        "crypto",
                        "balance",
                        "targeted",
                        "known_mnemonic",
                        result.symbol.lower(),
                    ],
                    raw_data={
                        "address": result.address,
                        "chain": result.chain,
                        "symbol": result.symbol,
                        "balance": result.balance,
                        "balance_raw": result.balance_raw,
                        "usd_price": result.usd_price,
                        "usd_value": result.usd_value,
                        "derivation_path": result.derivation_path,
                        "error": result.error,
                    },
                )
            )

        return TargetedScanResult(
            scan_id=scan_id,
            mode="known_mnemonic",
            findings=findings,
            addresses_checked=len(addresses),
            chains_checked=[c.name for c in self.chains],
            errors=errors,
            has_hits=any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings),
        )


class AccountRangeScan:
    """Scan a range of account indices for a single mnemonic on one chain.

    Useful for scanning accounts 0 through N to find funded wallets
    derived from the same seed phrase.

    Example::

        scanner = AccountRangeScan(mnemonic="abandon ...", chain=ETHEREUM, start=0, end=10)
        result = await scanner.execute()
    """

    def __init__(
        self,
        mnemonic: str,
        chain: ChainConfig,
        start: int = 0,
        end: int = 10,
    ):
        self.mnemonic = mnemonic.strip()
        if not is_valid_mnemonic(self.mnemonic):
            raise ValueError("Invalid BIP-39 mnemonic")
        if end <= start:
            raise ValueError("end must be greater than start")
        self.chain = chain
        self.start = start
        self.end = end

    async def execute(self, scan_id: str = "") -> TargetedScanResult:
        """Execute the account range scan.

        Returns:
            TargetedScanResult with findings for accounts with balance > 0.

        """
        if not is_valid_mnemonic(self.mnemonic):
            return TargetedScanResult(
                scan_id=scan_id,
                mode="account_range",
                errors=["Invalid BIP-39 mnemonic"],
            )

        findings: list[Finding] = []
        errors: list[str] = []
        addresses: list[DerivedAddress] = []

        # Derive one address per account index
        for account_idx in range(self.start, self.end):
            try:
                addrs = derive_from_mnemonic(
                    self.mnemonic,
                    chains=[self.chain],
                    account=account_idx,
                    count=1,
                )
                addresses.extend(addrs)
            except Exception as e:
                errors.append(f"Account {account_idx}: {e}")

        if not addresses:
            return TargetedScanResult(
                scan_id=scan_id,
                mode="account_range",
                errors=errors or ["No addresses derived"],
            )

        # Check balances
        balance_tasks = [check_balance(addr.address, self.chain, addr.derivation_path) for addr in addresses]
        balance_results = await asyncio.gather(*balance_tasks, return_exceptions=True)

        # Fetch USD prices
        prices = await get_usd_prices([self.chain.coin_id])

        # Build findings
        valid_results: list[BalanceResult] = []
        for i, result in enumerate(balance_results):
            if isinstance(result, Exception):
                errors.append(f"Account {self.start + i}: {result}")
                continue
            valid_results.append(result)  # type: ignore[arg-type]

        apply_usd_prices(valid_results, prices)

        for idx, result in enumerate(valid_results):
            account_idx = self.start + idx
            severity = Severity.INFO
            if result.balance > 0:
                severity = Severity.HIGH
            if result.usd_value > 1000:
                severity = Severity.CRITICAL

            title = f"Account {account_idx} — {result.chain}: {result.balance:.8f} {result.symbol}"
            if result.usd_price > 0:
                title += f" (~${result.usd_value:,.2f})"

            findings.append(
                Finding(
                    id=f"ar-{scan_id}-{account_idx}",
                    module="crypto_balance",
                    title=title,
                    description=f"Account range scan for {result.address} on {result.chain} (account {account_idx})",
                    severity=severity,
                    confidence=1.0,
                    tags=[
                        "crypto",
                        "balance",
                        "targeted",
                        "account_range",
                        result.symbol.lower(),
                    ],
                    raw_data={
                        "address": result.address,
                        "chain": result.chain,
                        "symbol": result.symbol,
                        "balance": result.balance,
                        "balance_raw": result.balance_raw,
                        "usd_price": result.usd_price,
                        "usd_value": result.usd_value,
                        "derivation_path": result.derivation_path,
                        "account_index": account_idx,
                        "error": result.error,
                    },
                )
            )

        return TargetedScanResult(
            scan_id=scan_id,
            mode="account_range",
            findings=findings,
            addresses_checked=len(addresses),
            chains_checked=[self.chain.name],
            errors=errors,
            has_hits=any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings),
        )


class FilteredRandomScan:
    """Random mnemonic generation with filtered balance checking.

    Generates random BIP-39 mnemonics, derives addresses, and checks
    balances. Only reports findings that meet the minimum balance threshold.

    Example::

        scanner = FilteredRandomScan(chains=[ETHEREUM], min_balance=0.001)
        result = await scanner.execute(iterations=100)
    """

    def __init__(
        self,
        chains: list[ChainConfig] | None = None,
        min_balance: float = 0.0,
        derivation_paths: list[str] | None = None,
    ):
        self.chains = chains or list(ALL_CHAINS)
        self.min_balance = min_balance
        self.derivation_paths = derivation_paths

    async def execute(
        self,
        scan_id: str = "",
        iterations: int = 10,
    ) -> TargetedScanResult:
        """Execute the filtered random scan.

        Args:
            scan_id: Unique scan identifier.
            iterations: Number of random mnemonics to generate and check.

        Returns:
            TargetedScanResult with findings meeting the min_balance threshold.

        """
        from bip_utils import Bip39Languages, Bip39MnemonicGenerator

        findings: list[Finding] = []
        errors: list[str] = []
        total_addresses = 0

        for i in range(iterations):
            # Generate a random 12-word mnemonic
            try:
                mnemonic = Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromWordsNumber(12)
            except Exception as e:
                errors.append(f"Iteration {i}: mnemonic generation failed: {e}")
                continue

            mnemonic_str = mnemonic.ToStr()

            # Derive addresses
            addresses: list[DerivedAddress] = []
            try:
                addrs = derive_from_mnemonic(mnemonic_str, chains=self.chains, count=1)

                # Filter by derivation paths if specified
                if self.derivation_paths:
                    addrs = [a for a in addrs if a.derivation_path in self.derivation_paths]

                addresses.extend(addrs)
            except Exception as e:
                errors.append(f"Iteration {i}: derivation failed: {e}")
                continue

            total_addresses += len(addresses)

            if not addresses:
                continue

            # Check balances
            balance_tasks = [
                check_balance(
                    addr.address,
                    chain_by_name(addr.chain, self.chains) or self.chains[0],
                    addr.derivation_path,
                )
                for addr in addresses
            ]
            balance_results = await asyncio.gather(*balance_tasks, return_exceptions=True)

            # Fetch USD prices
            coin_ids = list({c.coin_id for c in self.chains})
            prices = await get_usd_prices(coin_ids)

            # Apply prices and filter by min_balance
            valid_results: list[BalanceResult] = []
            for j, result in enumerate(balance_results):
                if isinstance(result, Exception):
                    continue
                valid_results.append(result)  # type: ignore[arg-type]

            apply_usd_prices(valid_results, prices)

            for result in valid_results:
                # Only report if balance meets threshold
                if result.balance < self.min_balance and result.usd_value < 0.01:
                    continue

                severity = Severity.INFO
                if result.balance > 0:
                    severity = Severity.HIGH
                if result.usd_value > 1000:
                    severity = Severity.CRITICAL

                title = f"{result.chain}: {result.balance:.8f} {result.symbol}"
                if result.usd_price > 0:
                    title += f" (~${result.usd_value:,.2f})"

                findings.append(
                    Finding(
                        id=f"fr-{scan_id}-{len(findings)}",
                        module="crypto_balance",
                        title=title,
                        description=f"Filtered random scan hit: {result.address} on {result.chain}",
                        severity=severity,
                        confidence=1.0,
                        tags=[
                            "crypto",
                            "balance",
                            "targeted",
                            "random",
                            result.symbol.lower(),
                        ],
                        raw_data={
                            "address": result.address,
                            "chain": result.chain,
                            "symbol": result.symbol,
                            "balance": result.balance,
                            "balance_raw": result.balance_raw,
                            "usd_price": result.usd_price,
                            "usd_value": result.usd_value,
                            "derivation_path": result.derivation_path,
                            "error": result.error,
                        },
                    )
                )

        return TargetedScanResult(
            scan_id=scan_id,
            mode="filtered_random",
            findings=findings,
            addresses_checked=total_addresses,
            chains_checked=[c.name for c in self.chains],
            errors=errors,
            has_hits=len(findings) > 0,
        )


def targeted_scan_to_scanresult(
    targeted: TargetedScanResult,
    target_label: str = "targeted",
) -> ScanResult:
    """Convert a TargetedScanResult to a standard ScanResult."""
    status = "ok" if not targeted.errors else "partial"
    if targeted.errors and not targeted.findings:
        status = "error"

    return ScanResult(
        scan_id=targeted.scan_id,
        module="crypto_balance",
        target=target_label,
        status=status,
        findings=targeted.findings,
        metadata={
            "mode": targeted.mode,
            "addresses_checked": targeted.addresses_checked,
            "chains_checked": targeted.chains_checked,
            "has_hits": targeted.has_hits,
            "errors": targeted.errors,
        },
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def chain_by_name(name: str, chains: list[ChainConfig]) -> ChainConfig | None:
    """Find a chain by name in a list."""
    return next((c for c in chains if c.name == name), None)
