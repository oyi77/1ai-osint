"""Deep Scan Engine — Recursive identity investigation.

Core engine that orchestrates recursive scanning across all modules.
Each finding is parsed for new identifiers, which feed back as inputs
until no new identifiers are discovered.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from src.models import ScanResult
from src.modules.deep_scan import (
    DeepScanResult, Identifier, IdentifierType,
)
from src.modules.deep_scan.extractor import extract_identifiers, extract_usernames_from_profiles

logger = logging.getLogger(__name__)

# Module → identifier types it can consume
_MODULE_INPUTS: dict[str, set[IdentifierType]] = {
    "social_osint": {IdentifierType.USERNAME, IdentifierType.NAME, IdentifierType.SOCIAL_PROFILE},
    "email_osint": {IdentifierType.EMAIL},
    "domain_recon": {IdentifierType.DOMAIN},
    "people_finder": {IdentifierType.USERNAME, IdentifierType.NAME},
    "phone_finder": {IdentifierType.PHONE},
    "data_leaks": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "crypto_balance": {IdentifierType.CRYPTO_ADDRESS},
    "gitleaks": {IdentifierType.DOMAIN, IdentifierType.URL},
    "vuln_scanner": {IdentifierType.DOMAIN, IdentifierType.IP},
    "dehashed": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE, IdentifierType.DOMAIN},
    "leakcheck": {IdentifierType.EMAIL, IdentifierType.USERNAME},
    "snylla": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE, IdentifierType.DOMAIN},
    "snusbase": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "hibp": {IdentifierType.EMAIL},
    "intelx": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE, IdentifierType.DOMAIN, IdentifierType.NAME},
}

# Sources handled by source_adapter (separate from CLI modules)
_SOURCE_MODULES = {"dehashed", "leakcheck", "snylla", "snusbase", "hibp", "intelx"}


class DeepScanEngine:
    """Recursive identity investigation engine.

    Takes an initial identifier and recursively discovers all connected
    identifiers across all modules until no new identifiers are found.
    """

    def __init__(
        self,
        max_iterations: int = 10,
        max_identifiers: int = 500,
        timeout_per_module: float = 60.0,
        modules: Optional[list[str]] = None,
    ):
        self.max_iterations = max_iterations
        self.max_identifiers = max_identifiers
        self.timeout_per_module = timeout_per_module
        self.modules = modules

    async def scan(self, target: str) -> DeepScanResult:
        """Run a deep scan on a target identifier."""
        started_at = datetime.now(timezone.utc)
        result = DeepScanResult(
            target=target,
            started_at=started_at,
            max_iterations=self.max_iterations,
        )

        # Detect initial identifier type
        initial = self._detect_identifier(target, "input")
        if initial:
            result.identifiers.append(initial)

        # Phase 1: Initial scan with the raw target
        logger.info("Deep scan starting: %s", target)
        await self._run_iteration(result, {target})

        # Phase 2: Recursive scanning with discovered identifiers
        seen_targets: set[str] = {target.lower()}
        for iteration in range(1, self.max_iterations):
            if len(result.identifiers) >= self.max_identifiers:
                logger.info("Max identifiers reached (%d)", self.max_identifiers)
                break

            # Collect new identifiers to scan
            new_targets = self._get_new_targets(result, seen_targets)
            if not new_targets:
                logger.info("No new identifiers found at iteration %d — stopping", iteration)
                break

            logger.info("Iteration %d: scanning %d new identifiers", iteration, len(new_targets))
            result.iterations = iteration
            await self._run_iteration(result, new_targets)
            seen_targets.update(t.lower() for t in new_targets)

        result.completed_at = datetime.now(timezone.utc)

        # ZKIT cross-module correlation
        try:
            result.zkit_result = self._run_zkit_correlation(result)
        except Exception as exc:
            logger.warning("ZKIT correlation failed: %s", exc)
            result.errors.append(f"zkit_correlation: {exc}")

        logger.info(
            "Deep scan complete: %d identifiers, %d findings, %d iterations, %.1fs",
            result.identifier_count, result.finding_count, result.iterations, result.duration_sec,
        )
        return result

    def _run_zkit_correlation(self, result: DeepScanResult) -> Optional[Any]:
        """Run ZKIT identity correlation on all collected scan results."""
        if not result.scan_results:
            return None
        from src.modules.identity_tracking.correlation import CrossModuleCorrelator
        from src.modules.identity_tracking.zkit_engine import ZKITEngine

        salt = ZKITEngine.new_salt()
        correlator = CrossModuleCorrelator(salt=salt)
        module_results = {sr.module: sr for sr in result.scan_results if sr.module}
        if not module_results:
            return None
        correlator.ingest_scan_results(module_results)
        return correlator.correlate()

    async def _run_iteration(self, result: DeepScanResult, targets: set[str]) -> None:
        """Run one iteration of scanning across all modules."""
        from src.cli import _get_module

        modules = self._get_active_modules()
        tasks = []

        for mod_name in modules:
            if mod_name in _SOURCE_MODULES:
                # Source adapter path
                from src.modules.sources import discover_sources

                all_sources = discover_sources()
                source_cls = all_sources.get(mod_name)
                if source_cls:
                    source_inst = source_cls()
                    relevant_targets = self._filter_targets_for_module(mod_name, targets, result)
                    for target in relevant_targets:
                        tasks.append(
                            self._scan_source_adapter(mod_name, source_inst, target, result)
                        )
                continue

            mod = _get_module(mod_name)
            if not mod:
                continue

            # Filter targets relevant to this module
            relevant_targets = self._filter_targets_for_module(mod_name, targets, result)
            if not relevant_targets:
                continue

            for target in relevant_targets:
                tasks.append(self._scan_module(mod_name, mod, target, result))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Extract new identifiers from all findings
        for finding in result.findings:
            raw = finding.raw_data or {}
            text = str(raw)
            new_ids = extract_identifiers(text, finding.module)
            for nid in new_ids:
                self._add_identifier(result, nid)

        # Extract usernames from social media profiles
        profile_ids = extract_usernames_from_profiles(result.findings)
        for pid in profile_ids:
            self._add_identifier(result, pid)

    async def _scan_module(
        self, mod_name: str, mod: Any, target: str, result: DeepScanResult,
    ) -> None:
        """Run a single module scan."""
        try:
            scan_result = await asyncio.wait_for(
                mod.scan(target), timeout=self.timeout_per_module,
            )
            if isinstance(scan_result, ScanResult):
                result.scan_results.append(scan_result)
                for finding in scan_result.findings:
                    result.findings.append(finding)
        except asyncio.TimeoutError:
            result.errors.append(f"{mod_name}({target}): timeout")
        except Exception as exc:
            result.errors.append(f"{mod_name}({target}): {exc}")

    async def _scan_source_adapter(
        self, source_name: str, source_inst: Any, target: str, result: DeepScanResult,
    ) -> None:
        """Run a breach/leak source via the source adapter."""
        try:
            from src.modules.deep_scan.source_adapter import run_source_scan
            scan_result = await asyncio.wait_for(
                run_source_scan(source_name, target, source_inst),
                timeout=self.timeout_per_module,
            )
            if isinstance(scan_result, ScanResult):
                result.scan_results.append(scan_result)
                for finding in scan_result.findings:
                    result.findings.append(finding)
        except asyncio.TimeoutError:
            result.errors.append(f"source_{source_name}({target}): timeout")
        except Exception as exc:
            result.errors.append(f"source_{source_name}({target}): {exc}")

    def _get_new_targets(self, result: DeepScanResult, seen: set[str]) -> set[str]:
        """Extract new targets from discovered identifiers."""
        targets: set[str] = set()
        for ident in result.identifiers:
            if ident.value.lower() in seen:
                continue
            # Skip low-confidence identifiers
            if ident.confidence < 0.3:
                continue
            targets.add(ident.value)
        return targets

    def _filter_targets_for_module(
        self, mod_name: str, targets: set[str], result: DeepScanResult,
    ) -> set[str]:
        """Filter targets to only those relevant to a module."""
        accepted_types = _MODULE_INPUTS.get(mod_name, set())
        if not accepted_types:
            # Module not in mapping — pass all targets
            return targets

        filtered: set[str] = set()
        for target in targets:
            # Find the identifier for this target
            for ident in result.identifiers:
                if ident.value == target and ident.id_type in accepted_types:
                    filtered.add(target)
                    break
            else:
                # Target not in identifiers — try to detect type
                detected = self._detect_identifier(target, "filter")
                if detected and detected.id_type in accepted_types:
                    filtered.add(target)

        return filtered

    def _add_identifier(self, result: DeepScanResult, ident: Identifier) -> None:
        """Add an identifier if not already present."""
        for existing in result.identifiers:
            if existing.value.lower() == ident.value.lower() and existing.id_type == ident.id_type:
                # Update last_seen
                existing.last_seen = ident.first_seen
                return
        if len(result.identifiers) < self.max_identifiers:
            result.identifiers.append(ident)

    def _get_active_modules(self) -> list[str]:
        """Get list of modules to use."""
        if self.modules:
            return self.modules
        return list(_MODULE_INPUTS.keys())

    @staticmethod
    def _detect_identifier(value: str, source: str) -> Optional[Identifier]:
        """Auto-detect the type of an identifier."""
        import re
        value = value.strip()

        if not value:
            return None

        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return Identifier(value=value.lower(), id_type=IdentifierType.EMAIL, source=source)

        # Phone
        if re.match(r'^[\+]?[0-9]{7,15}$', re.sub(r'[\s\-\.\(\)]', '', value)):
            return Identifier(value=value, id_type=IdentifierType.PHONE, source=source)

        # Ethereum address
        if re.match(r'^0x[0-9a-fA-F]{40}$', value):
            return Identifier(value=value, id_type=IdentifierType.CRYPTO_ADDRESS, source=source, metadata={"chain": "ethereum"})

        # IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return Identifier(value=value, id_type=IdentifierType.IP, source=source)

        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', value):
            return Identifier(value=value.lower(), id_type=IdentifierType.DOMAIN, source=source)

        # NIK (16 digits)
        if re.match(r'^\d{16}$', value):
            return Identifier(value=value, id_type=IdentifierType.NIK, source=source)

        # Default to username
        if re.match(r'^[a-zA-Z0-9_.-]{3,50}$', value):
            return Identifier(value=value, id_type=IdentifierType.USERNAME, source=source)

        # Default to name
        return Identifier(value=value, id_type=IdentifierType.NAME, source=source)
