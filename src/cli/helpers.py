"""Shared CLI helpers — module resolution, AI analysis, ZKIT tracking."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from src.core.models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Plugin system
# ---------------------------------------------------------------------------
_plugin_registry: Any = None


def init_plugins() -> Any:
    """Lazy-init the global plugin registry and discover plugins."""
    from src.plugin import PluginRegistry

    global _plugin_registry  # noqa: PLW0603
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry()
        _plugin_registry.discover()
    return _plugin_registry


# ---------------------------------------------------------------------------
# Module resolver
# ---------------------------------------------------------------------------
def get_module(name: str, zkit_salt: str = "") -> Any:
    """Resolve a module name to its tool instance."""
    if name in ("gitleaks", "secrets"):
        from src.modules.gitleaks.scanner import GitleaksModule

        return GitleaksModule(zkit_salt=zkit_salt)
    elif name in ("data_leaks", "breaches", "leaks"):
        from src.modules.data_leaks.aggregator import DataLeaksAggregator

        return DataLeaksAggregator(zkit_salt=zkit_salt)
    elif name in ("people", "people_finder"):
        from src.modules.people_finder.search import PeopleFinderSearch

        return PeopleFinderSearch(zkit_salt=zkit_salt)
    elif name in ("phone", "phone_finder"):
        from src.modules.phone_finder import PhoneFinderTool

        return PhoneFinderTool(zkit_salt=zkit_salt)
    elif name in ("gc_lookup", "getcontact"):
        from src.modules.phone_finder.gc_lookup import GCLookupTool

        return GCLookupTool(zkit_salt=zkit_salt)
    elif name in ("phone_intel", "phoneintel"):
        from src.modules.phone_intel import PhoneIntelTool

        return PhoneIntelTool(zkit_salt=zkit_salt)
    elif name in ("crypto_passphrase", "passphrase"):
        from src.modules.crypto.passphrase.generator import generate_with_details

        return _PassphraseModule(generate_with_details, zkit_salt=zkit_salt)
    elif name in ("crypto_privatekey", "privatekey", "privkey"):
        from src.modules.crypto.privatekey.scanner import PrivateKeyScanner

        return PrivateKeyScanner(zkit_salt=zkit_salt)
    elif name in ("crypto_balance", "balance", "wallet"):
        from src.modules.crypto.balance import CryptoBalanceTool

        return CryptoBalanceTool(zkit_salt=zkit_salt)
    elif name in ("crypto_tracer", "tx_tracer"):
        from src.modules.crypto.tx_tracer import BlockchainTxTracer

        return BlockchainTxTracer(zkit_salt=zkit_salt)
    elif name in ("domain", "domain_recon"):
        from src.modules.domain_recon import DomainReconTool

        return DomainReconTool(zkit_salt=zkit_salt)
    elif name in ("email", "email_osint"):
        from src.modules.email_osint import EmailOSINTTool

        return EmailOSINTTool(zkit_salt=zkit_salt)
    elif name in ("social", "social_osint"):
        from src.modules.social_osint import SocialOSINTTool

        return SocialOSINTTool(zkit_salt=zkit_salt)
    elif name in ("vuln", "vuln_scanner"):
        from src.modules.vuln_scanner import VulnScannerTool

        return VulnScannerTool()
    return None


# ---------------------------------------------------------------------------
# Passphrase module adapter
# ---------------------------------------------------------------------------
class _PassphraseModule:
    """Thin adapter wrapping the passphrase generator as a scannable module."""

    name = "crypto_passphrase"
    description = "BIP-39 mnemonic passphrase generation and analysis"
    version = "0.1.0"

    def __init__(self, gen_func: Any, zkit_salt: str = ""):
        self._gen_func = gen_func
        self.zkit_salt = zkit_salt

    async def scan(self, target: str, **kwargs: Any) -> ScanResult:
        scan_id = f"passphrase-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        started_at = datetime.now(timezone.utc)
        findings = []

        try:
            details = self._gen_func(word_count=24, language="english")
            findings.append(
                Finding(
                    id=f"fp-{scan_id}",
                    module=self.name,
                    title="BIP-39 mnemonic generated",
                    description=f"Generated {details['word_count']}-word mnemonic ({details['entropy_bits']} bits entropy)",
                    severity=Severity.INFO,
                    raw_data=details,
                    confidence=1.0,
                    tags=["crypto", "passphrase", "bip39"],
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    id=f"fp-err-{scan_id}",
                    module=self.name,
                    title="Passphrase generation error",
                    description=str(e),
                    severity=Severity.HIGH,
                    raw_data={"error": str(e)},
                    confidence=1.0,
                    tags=["crypto", "passphrase", "error"],
                )
            )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            metadata={"word_count": 24},
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# AI analysis runner
# ---------------------------------------------------------------------------
def run_with_ai(result: ScanResult, ai_enabled: bool) -> ScanResult:
    """Optionally run AI analysis on scan results."""
    if not ai_enabled:
        return result

    try:
        from src.ai.orchestrator import AnalysisOrchestrator

        orchestrator = AnalysisOrchestrator()
        report = asyncio.run(orchestrator.run(scan_results=[result]))
        result.metadata["ai_report"] = report
    except Exception as e:
        result.metadata["ai_error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# ZKIT identity tracking runner
# ---------------------------------------------------------------------------
def run_zkit_tracking(result: ScanResult, zkit_salt: str) -> ScanResult:
    """Run ZKIT identity tracking on scan results."""
    if not zkit_salt:
        return result

    try:
        from src.modules.identity_tracking.identity_graph import IdentityGraph, NodeType

        graph = IdentityGraph(salt=zkit_salt)

        for finding in result.findings:
            raw = finding.raw_data or {}
            email = raw.get("email") or raw.get("Email")
            username = raw.get("username") or raw.get("Username")
            phone = raw.get("phone")
            domain = raw.get("domain") or raw.get("Domain")

            attrs = []
            if email:
                attrs.append((email, NodeType.EMAIL_HASH))
            if username:
                attrs.append((username, NodeType.USERNAME_HASH))
            if phone:
                attrs.append((phone, NodeType.PHONE_HASH))
            if domain:
                attrs.append((domain, NodeType.DOMAIN_HASH))

            for raw_val, node_type in attrs:
                graph.add_raw_attribute(raw_val, node_type, source=result.module)

            for i in range(len(attrs)):
                for j in range(i + 1, len(attrs)):
                    graph.add_co_occurrence(
                        attrs[i][0],
                        attrs[i][1],
                        attrs[j][0],
                        attrs[j][1],
                        source=result.module,
                    )

        result.metadata["zkit_graph"] = {
            "nodes": graph.node_count,
            "edges": graph.edge_count,
        }
    except Exception as e:
        result.metadata["zkit_error"] = str(e)

    return result
