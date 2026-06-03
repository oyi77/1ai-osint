"""CryptoBalanceTool — derive addresses and check on-chain balances."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.modules.crypto.balance.chains import ALL_CHAINS, CHAIN_MAP, ChainConfig
from src.modules.crypto.balance.deriver import (
    DerivedAddress,
    derive_from_mnemonic,
    derive_from_privatekey,
    detect_input_type,
)
from src.modules.crypto.balance.checker import (
    BalanceResult,
    apply_usd_prices,
    check_balance,
    get_usd_prices,
)
from src.modules.crypto.balance.targeted_search import (
    KnownMnemonicLookup,
    targeted_scan_to_scanresult,
)

logger = logging.getLogger(__name__)


def _chain_for_address_type(
    input_type: str, chains: list[ChainConfig]
) -> Optional[ChainConfig]:
    """Determine chain from address type."""
    mapping = {
        "btc_address": "Bitcoin",
        "evm_address": "Ethereum",
        "sol_address": "Solana",
    }
    name = mapping.get(input_type)
    if name:
        return next((c for c in chains if c.name == name), None)
    return None


def _chain_by_name(name: str, chains: list[ChainConfig]) -> Optional[ChainConfig]:
    """Find chain config by name."""
    return next((c for c in chains if c.name == name), None)


class CryptoBalanceTool(BaseOSINTTool):
    """Derive wallet addresses from mnemonics/keys and check on-chain balances.

    Supports BTC (BIP-44/49/84), ETH, BSC, Polygon, and SOL.
    Uses free public APIs — no API keys required.
    """

    name = "crypto_balance"
    description = (
        "Derive wallet addresses and check on-chain balances (BTC/ETH/BSC/Polygon/SOL)"
    )
    version = "0.1.0"

    def __init__(
        self,
        chains: Optional[list[ChainConfig]] = None,
        account_count: int = 1,
        zkit_salt: Optional[str] = None,
    ):
        super().__init__(zkit_salt=zkit_salt)
        self.chains = chains or list(ALL_CHAINS)
        self.account_count = account_count

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Search is an alias for scan."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan: derive addresses and check balances.

        Args:
            target: BIP-39 mnemonic, private key (hex), or blockchain address.
                   For random scan_mode, this is ignored (pass "random" or empty).
            **kwargs:
                account_count (int): Number of address indices to derive per chain.
                chains (list[str]): Chain names to filter.
                scan_mode (str): "random" or "targeted" (default: auto-detect).
                account_range (tuple[int,int]): Account range for targeted mode (default: (0,1)).
                min_balance (float): Min balance for filtered random scan (default: 0.0).
                derivation_paths (list[str]): Filter derivation paths for random scan.
                iterations (int): Number of random mnemonics for filtered random scan (default: 10).

        Returns:
            ScanResult with one Finding per address/chain combination.
        """
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []

        account_count = kwargs.get("account_count", self.account_count)
        scan_mode = kwargs.get("scan_mode", "")
        input_type = detect_input_type(target)

        # --- Targeted scan mode delegation ---
        # If scan_mode is explicitly "targeted" and input is a mnemonic, use targeted search
        if scan_mode == "targeted" and input_type == "mnemonic":
            return await self._run_targeted_scan(target, scan_id, started_at, **kwargs)

        # If scan_mode is explicitly "random", delegate to RandomScanner
        if scan_mode == "random":
            return await self._run_random_scan(scan_id, started_at, **kwargs)

        # If scan_mode is "leak", delegate to leak scanner
        if scan_mode == "leak":
            return await self._run_leak_scan(scan_id, started_at, **kwargs)

        # If scan_mode is "leak_key", delegate to private key leak scanner
        if scan_mode == "leak_key":
            return await self._run_leak_key_scan(scan_id, started_at, **kwargs)

        # If scan_mode is "leak_telegram", delegate to Telegram leak scanner
        if scan_mode == "leak_telegram":
            return await self._run_leak_telegram_scan(scan_id, started_at, **kwargs)

        # If scan_mode is "smart", delegate to smart generator
        if scan_mode == "smart":
            return await self._run_smart_scan(scan_id, started_at, **kwargs)

        # If input is "random" literal, run random scan
        if target.strip().lower() == "random":
            return await self._run_random_scan(scan_id, started_at, **kwargs)

        if input_type == "unknown":
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target[:20] + "...",
                status="error",
                error="Could not detect input type. Provide a valid mnemonic, private key, or address.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        # Resolve chain filter from kwargs
        chain_filter = kwargs.get("chains")
        active_chains = self.chains
        if chain_filter:
            active_chains = [
                CHAIN_MAP[c.lower()] for c in chain_filter if c.lower() in CHAIN_MAP
            ]

        # Step 1: Derive or resolve addresses
        addresses: list[DerivedAddress] = []
        if input_type == "mnemonic":
            addresses = derive_from_mnemonic(
                target, chains=active_chains, count=account_count
            )
        elif input_type == "private_key":
            # Try to derive for each chain (ETH-like keys work for ETH/BSC/Polygon)
            for chain in active_chains:
                try:
                    addr = derive_from_privatekey(target, chain=chain)
                    addresses.append(addr)
                except Exception as e:
                    errors.append(f"{chain.name}: {e}")
        elif input_type in ("btc_address", "evm_address", "sol_address"):
            # Direct address — determine chain and check balance
            chain = _chain_for_address_type(input_type, active_chains)
            if chain:
                addresses.append(
                    DerivedAddress(
                        address=target.strip(),
                        chain=chain.name,
                        symbol=chain.symbol,
                        derivation_path="direct",
                    )
                )

        if not addresses:
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target[:20] + "...",
                status="error",
                error=f"No addresses derived. Errors: {'; '.join(errors)}"
                if errors
                else "No addresses derived.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        # Step 2: Check balances concurrently
        balance_tasks = [
            check_balance(
                addr.address,
                _chain_by_name(addr.chain, active_chains) or active_chains[0],
                addr.derivation_path,
            )
            for addr in addresses
        ]
        balance_results = await asyncio.gather(*balance_tasks, return_exceptions=True)

        # Step 3: Fetch USD prices
        coin_ids = list({c.coin_id for c in active_chains})
        prices = await get_usd_prices(coin_ids)

        # Step 4: Apply prices and build findings
        valid_results: list[BalanceResult] = []
        for i, result in enumerate(balance_results):
            if isinstance(result, Exception):
                errors.append(f"{addresses[i].chain}: {result}")
                continue
            valid_results.append(result)

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
                    id=self._make_finding_id(),
                    module=self.name,
                    title=title,
                    description=f"Balance for {result.address} on {result.chain}",
                    severity=severity,
                    confidence=1.0,
                    tags=[
                        "crypto",
                        "balance",
                        result.symbol.lower(),
                        result.chain.lower(),
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

        status = "ok" if not errors else "partial"
        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=input_type,
            status=status,
            findings=findings,
            metadata={
                "input_type": input_type,
                "addresses_checked": len(addresses),
                "chains_checked": [c.name for c in active_chains],
                "errors": errors,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze scan results — aggregate balances by chain."""
        if isinstance(data, ScanResult):
            findings = data.findings
        elif isinstance(data, list):
            findings = data
        else:
            return {"error": "Expected ScanResult or list of Findings"}

        by_chain: dict[str, dict] = {}
        total_usd = 0.0

        for f in findings:
            chain = f.raw_data.get("chain", "unknown")
            if chain not in by_chain:
                by_chain[chain] = {
                    "balance": 0.0,
                    "usd_value": 0.0,
                    "symbol": f.raw_data.get("symbol", ""),
                    "addresses": [],
                }
            by_chain[chain]["balance"] += f.raw_data.get("balance", 0)
            by_chain[chain]["usd_value"] += f.raw_data.get("usd_value", 0)
            by_chain[chain]["addresses"].append(f.raw_data.get("address", ""))
            total_usd += f.raw_data.get("usd_value", 0)

        return {
            "total_usd_value": total_usd,
            "by_chain": by_chain,
            "findings_count": len(findings),
            "has_funds": total_usd > 0,
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """No-op — future: watch addresses for balance changes."""
        pass

    async def _run_targeted_scan(
        self, target: str, scan_id: str, started_at: datetime, **kwargs
    ) -> ScanResult:
        """Delegate to targeted search for a known mnemonic."""
        account_range = kwargs.get("account_range", (0, self.account_count))
        chain_filter = kwargs.get("chains")
        active_chains = self.chains
        if chain_filter:
            active_chains = [
                CHAIN_MAP[c.lower()] for c in chain_filter if c.lower() in CHAIN_MAP
            ]

        lookup = KnownMnemonicLookup(
            mnemonic=target,
            chains=active_chains,
            account_range=account_range,
        )
        targeted_result = await lookup.execute(scan_id=scan_id)
        scan_result = targeted_scan_to_scanresult(
            targeted_result, target_label="targeted"
        )
        scan_result.started_at = started_at
        scan_result.completed_at = datetime.now(timezone.utc)
        return scan_result

    async def _run_random_scan(
        self, scan_id: str, started_at: datetime, **kwargs
    ) -> ScanResult:
        """Delegate to RandomScanner for random mnemonic scanning."""
        from src.modules.crypto.balance.scanner_engine import RandomScanner

        duration = kwargs.get("duration")
        workers = kwargs.get("workers", 20)

        scanner = RandomScanner(
            workers=workers,
            chains=self.chains,
        )
        stats = await scanner.run(duration_sec=duration)

        findings: list[Finding] = []
        findings.append(
            Finding(
                id=f"random-scan-{scan_id}",
                module=self.name,
                title="Random scan completed",
                description=(
                    f"Generated {stats.mnemonics_generated} mnemonics at "
                    f"{stats.mnemonics_per_sec:.1f}/sec, "
                    f"{stats.hits_found} hits, {stats.api_errors} errors"
                ),
                severity=Severity.HIGH if stats.hits_found > 0 else Severity.INFO,
                confidence=1.0,
                tags=["crypto", "random_scan", "summary"],
                raw_data={
                    "mnemonics_generated": stats.mnemonics_generated,
                    "addresses_checked": stats.addresses_checked,
                    "hits_found": stats.hits_found,
                    "api_errors": stats.api_errors,
                    "elapsed_seconds": stats.elapsed,
                    "mnemonics_per_sec": stats.mnemonics_per_sec,
                },
            )
        )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target="random",
            status="ok",
            findings=findings,
            metadata={
                "mode": "random",
                "workers": workers,
                "duration": duration,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def _run_leak_scan(
        self, scan_id: str, started_at: datetime, **kwargs
    ) -> ScanResult:
        """Delegate to leak scanner (GitHub + Pastebin) for leaked mnemonic discovery."""
        from src.modules.crypto.balance.leak_scanner import (
            GitHubLeakScanner,
            PasteSiteScanner,
            verify_and_alert,
        )
        from src.modules.crypto.balance.hit_logger import HitLogger
        from src.modules.crypto.balance.scanner_coordinator import ScannerCoordinator
        import os

        hit_logger = HitLogger(
            db_path="wallet_hits.db",
            telegram_token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
        )
        await hit_logger.start()

        coordinator = ScannerCoordinator(chains=self.chains)
        await coordinator.start()

        github_token = os.environ.get("GITHUB_TOKEN", "")
        github_scanner = GitHubLeakScanner(
            github_token=github_token, hit_logger=hit_logger
        )
        paste_scanner = PasteSiteScanner(hit_logger=hit_logger)

        total_candidates = 0
        total_hits = 0
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            # GitHub scan
            github_findings = await github_scanner.scan(max_results=30)
            total_candidates += len(github_findings)

            for finding in github_findings:
                if not coordinator.is_mnemonic_seen(finding.mnemonic_candidate):
                    coordinator.mark_mnemonic_seen(
                        finding.mnemonic_candidate, source="leak"
                    )
                    result = await verify_and_alert(
                        finding.mnemonic_candidate,
                        chains=self.chains,
                        hit_logger=hit_logger,
                    )
                    if result and result.has_balance:
                        total_hits += 1

            # Pastebin scan
            paste_findings = await paste_scanner.scan(max_pastes=30)
            total_candidates += len(paste_findings)

            for finding in paste_findings:
                if not coordinator.is_mnemonic_seen(finding.mnemonic_candidate):
                    coordinator.mark_mnemonic_seen(
                        finding.mnemonic_candidate, source="leak"
                    )
                    result = await verify_and_alert(
                        finding.mnemonic_candidate,
                        chains=self.chains,
                        hit_logger=hit_logger,
                    )
                    if result and result.has_balance:
                        total_hits += 1

        except Exception as e:
            errors.append(str(e))
        finally:
            await coordinator.stop()
            await hit_logger.close()

        findings.append(
            Finding(
                id=f"leak-scan-{scan_id}",
                module=self.name,
                title="Leak scan completed",
                description=(
                    f"Found {total_candidates} mnemonic candidates from GitHub/Pastebin, "
                    f"{total_hits} confirmed hits"
                ),
                severity=Severity.HIGH if total_hits > 0 else Severity.INFO,
                confidence=1.0,
                tags=["crypto", "leak_scan", "summary"],
                raw_data={
                    "candidates_found": total_candidates,
                    "hits_confirmed": total_hits,
                    "errors": errors,
                },
            )
        )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target="leak",
            status="ok" if not errors else "partial",
            findings=findings,
            metadata={
                "mode": "leak",
                "candidates": total_candidates,
                "hits": total_hits,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def _run_leak_key_scan(
        self, scan_id: str, started_at: datetime, **kwargs
    ) -> ScanResult:
        """Delegate to KeyLeakScanner for leaked private key discovery."""
        from src.modules.crypto.balance.leak_scanner import (
            KeyLeakScanner,
            verify_and_alert_key,
        )
        from src.modules.crypto.balance.hit_logger import HitLogger

        import os

        hit_logger = HitLogger(
            db_path="wallet_hits.db",
            telegram_token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
        )
        await hit_logger.start()

        github_token = os.environ.get("GITHUB_TOKEN", "")
        key_scanner = KeyLeakScanner(github_token=github_token, hit_logger=hit_logger)

        total_candidates = 0
        total_hits = 0
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            key_findings = await key_scanner.scan(max_results=30, max_pastes=30)
            total_candidates += len(key_findings)

            for finding in key_findings:
                result = await verify_and_alert_key(
                    finding.mnemonic_candidate,
                    chains=self.chains,
                    hit_logger=hit_logger,
                    source=finding.source,
                )
                if result and result.has_balance:
                    total_hits += 1

        except Exception as e:
            errors.append(str(e))
        finally:
            await hit_logger.close()

        findings.append(
            Finding(
                id=f"leak-key-scan-{scan_id}",
                module=self.name,
                title="Private key leak scan completed",
                description=(
                    f"Found {total_candidates} private key candidates from GitHub/Pastebin, "
                    f"{total_hits} confirmed hits"
                ),
                severity=Severity.HIGH if total_hits > 0 else Severity.INFO,
                confidence=1.0,
                tags=["crypto", "leak_key_scan", "summary"],
                raw_data={
                    "candidates_found": total_candidates,
                    "hits_confirmed": total_hits,
                    "errors": errors,
                },
            )
        )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target="leak_key",
            status="ok" if not errors else "partial",
            findings=findings,
            metadata={
                "mode": "leak_key",
                "candidates": total_candidates,
                "hits": total_hits,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def _run_leak_telegram_scan(
        self, scan_id: str, started_at: datetime, **kwargs
    ) -> ScanResult:
        """Scan Telegram channels for leaked private keys using Telethon."""
        from src.modules.crypto.balance.leak_scanner_telegram import (
            run_telegram_leak_scan,
        )
        from src.modules.crypto.balance.leak_scanner import verify_and_alert_key
        from src.modules.crypto.balance.hit_logger import HitLogger
        import os

        hit_logger = HitLogger(
            db_path="wallet_hits.db",
            telegram_token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
        )
        await hit_logger.start()

        channels = kwargs.get("channels", None)
        auto_discover = kwargs.get("auto_discover", True)

        findings = await run_telegram_leak_scan(
            channels=channels,
            auto_discover=auto_discover,
            hit_logger=hit_logger,
        )

        total_hits = 0
        for finding in findings:
            try:
                result = await verify_and_alert_key(
                    finding.mnemonic_candidate,
                    hit_logger=hit_logger,
                    source="telegram",
                )
                if result and result.has_balance:
                    total_hits += 1
            except Exception as e:
                logger.debug("Telegram finding verification error: %s", e)

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target="leak_telegram",
            status="ok",
            findings=findings,
            metadata={
                "mode": "leak_telegram",
                "candidates": len(findings),
                "hits": total_hits,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def _run_smart_scan(
        self, scan_id: str, started_at: datetime, **kwargs
    ) -> ScanResult:
        """Delegate to smart generator for AI word-frequency biased scanning."""
        from src.modules.crypto.balance.ai_analyzer import WordFrequencyAnalyzer
        from src.modules.crypto.balance.smart_generator import SmartMnemonicGenerator
        from src.modules.crypto.balance.scanner_coordinator import ScannerCoordinator
        from src.modules.crypto.balance.hit_logger import HitLogger
        from src.modules.crypto.balance.deriver import derive_from_mnemonic
        import os

        iterations = kwargs.get("iterations", 10)
        hit_logger = HitLogger(
            db_path="wallet_hits.db",
            telegram_token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
        )
        await hit_logger.start()

        coordinator = ScannerCoordinator(chains=self.chains)
        await coordinator.start()

        analyzer = WordFrequencyAnalyzer()
        analyzer.load_from_db()
        generator = SmartMnemonicGenerator(analyzer)

        total_generated = 0
        total_hits = 0
        errors: list[str] = []
        findings: list[Finding] = []

        try:
            for _ in range(iterations):
                mnemonic = generator.generate()
                if coordinator.is_mnemonic_seen(mnemonic):
                    continue
                coordinator.mark_mnemonic_seen(mnemonic, source="smart")
                total_generated += 1

                addresses = derive_from_mnemonic(mnemonic, chains=self.chains, count=1)
                for addr in addresses:
                    try:
                        result = await coordinator.check_balance(
                            addr.address,
                            next(c for c in self.chains if c.name == addr.chain),
                            addr.derivation_path,
                        )
                        if result.balance > 0:
                            total_hits += 1
                            mnemonic_hash = ScannerCoordinator.hash_mnemonic(mnemonic)
                            await hit_logger.log_hit(
                                address=addr.address,
                                chain=addr.chain,
                                balance=result.balance,
                                mnemonic_hash=mnemonic_hash,
                                derivation_path=addr.derivation_path,
                                source="smart",
                            )
                            findings.append(
                                Finding(
                                    id=f"smart-{mnemonic_hash[:12]}",
                                    module="crypto.balance",
                                    severity=Severity.HIGH,
                                    title="Funded wallet found via smart generation",
                                    description=f"Balance: {result.balance} on {addr.chain}",
                                    raw_data={
                                        "mnemonic_hash": mnemonic_hash,
                                        "chain": addr.chain,
                                    },
                                )
                            )
                    except Exception as e:
                        errors.append(f"{addr.chain}/{addr.address}: {e}")

        finally:
            await coordinator.stop()
            await hit_logger.close()

        return ScanResult(
            scan_id="smart-scan",
            module="crypto.balance",
            target="smart-generator",
            findings=findings,
            metadata={
                "total_generated": total_generated,
                "total_hits": total_hits,
                "errors": errors,
            },
        )
