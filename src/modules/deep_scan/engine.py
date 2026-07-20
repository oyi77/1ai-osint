"""Deep Scan Engine — Recursive identity investigation.

Core engine that orchestrates recursive scanning across all modules.
Each finding is parsed for new identifiers, which feed back as inputs
until no new identifiers are discovered.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Optional

from src.core.models import ScanResult
from src.modules.deep_scan import (
    DeepScanResult,
    Identifier,
    IdentifierType,
)
from src.modules.deep_scan.extractor import (
    extract_identifiers,
    extract_usernames_from_profiles,
)
from src.modules.deep_scan.free_intel_adapter import list_free_intel_modules

logger = logging.getLogger(__name__)

# Module → identifier types it can consume
_MODULE_INPUTS: dict[str, set[IdentifierType]] = {
    "social_osint": {
        IdentifierType.USERNAME,
        IdentifierType.NAME,
        IdentifierType.SOCIAL_PROFILE,
    },
    "email_osint": {IdentifierType.EMAIL},
    "domain_recon": {IdentifierType.DOMAIN},
    "people_finder": {IdentifierType.USERNAME, IdentifierType.NAME},
    "phone_finder": {IdentifierType.PHONE},
    "data_leaks": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "crypto_balance": {IdentifierType.CRYPTO_ADDRESS},
    "gitleaks": {IdentifierType.DOMAIN, IdentifierType.URL},
    "vuln_scanner": {IdentifierType.DOMAIN, IdentifierType.IP},
    "dehashed": {
        IdentifierType.EMAIL,
        IdentifierType.USERNAME,
        IdentifierType.PHONE,
        IdentifierType.DOMAIN,
    },
    "leakcheck": {IdentifierType.EMAIL, IdentifierType.USERNAME},
    "snylla": {
        IdentifierType.EMAIL,
        IdentifierType.USERNAME,
        IdentifierType.PHONE,
        IdentifierType.DOMAIN,
    },
    "snusbase": {IdentifierType.EMAIL, IdentifierType.USERNAME, IdentifierType.PHONE},
    "hibp": {IdentifierType.EMAIL},
    "intelx": {
        IdentifierType.EMAIL,
        IdentifierType.USERNAME,
        IdentifierType.PHONE,
        IdentifierType.DOMAIN,
        IdentifierType.NAME,
    },
    # Free intel modules (search engine dorking, gravatar, wayback)
    "social_dorks_intel": {IdentifierType.NAME},
    "gravatar_intel": {IdentifierType.EMAIL},
    "wayback_intel": {IdentifierType.URL},
    "github_intel": {IdentifierType.USERNAME},
    "google_dork_intel": {IdentifierType.NAME},
    "hibp_free": {IdentifierType.EMAIL},
    "bts_intel": {IdentifierType.PHONE},
    "pddikti_intel": {IdentifierType.NAME},
    "tech_jobs_intel": {IdentifierType.NAME},
    "whatsapp_check": {IdentifierType.PHONE},
    "telegram_check": {IdentifierType.USERNAME},
}
_FREE_INTEL_MODULES: set[str] = set(list_free_intel_modules())

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
        *,
        fast: bool = False,
        max_concurrency: int = 24,
        max_pivot_handles: int = 5,
        budget: float = 5.0,
        max_targets_per_iteration: int = 25,
        profile_config: Any = None,
    ):
        if profile_config is not None:
            max_iterations = profile_config.max_iterations
            timeout_per_module = profile_config.timeout_per_module
            max_identifiers = profile_config.max_identifiers
            max_pivot_handles = profile_config.max_pivot_handles
            max_targets_per_iteration = profile_config.max_targets_per_iteration
            max_concurrency = profile_config.max_concurrency
            fast = profile_config.fast_mode
            modules = list(profile_config.modules)
        elif fast:
            from src.modules.deep_scan.profiles import (
                fast_module_list,
                fast_scan_defaults,
            )

            defaults = fast_scan_defaults()
            max_iterations = min(max_iterations, int(defaults["max_iterations"]))
            timeout_per_module = min(timeout_per_module, float(defaults["timeout_per_module"]))
            max_identifiers = min(max_identifiers, int(defaults["max_identifiers"]))
            max_pivot_handles = int(defaults["max_pivot_handles"])
            max_targets_per_iteration = int(defaults["max_targets_per_iteration"])
            max_concurrency = int(defaults["max_concurrency"])
            if modules is None:
                modules = fast_module_list()

        self.max_iterations = max_iterations
        self.max_identifiers = max_identifiers
        self.timeout_per_module = timeout_per_module
        self.modules = set(modules) if modules else set(_MODULE_INPUTS.keys())
        self.fast = fast
        self.max_concurrency = max_concurrency
        self.max_pivot_handles = max_pivot_handles
        self.budget = budget
        self.max_targets_per_iteration = max_targets_per_iteration
        self._sem = asyncio.Semaphore(max_concurrency)
        self._scanned_pairs: set[tuple[str, str]] = set()

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
            if initial.id_type == IdentifierType.NAME:
                from src.modules.deep_scan.name_pivots import (
                    username_candidates_from_name,
                )

                pivots = username_candidates_from_name(target)[: self.max_pivot_handles]

                # Verify handle existence before trusting name-permuted handles.
                # This prevents the misattribution bug where a handle derived from
                # a name (e.g. "izzuddinfikri" from "Fikri Izzuddin") gets scanned
                # even though it belongs to a different person.
                _unverified: set[str] = set()
                try:
                    from src.modules.deep_scan.handle_verifier import (
                        batch_verify_handles,
                    )

                    handle_handles = [h for h, _ in pivots]
                    _verifications = await batch_verify_handles(handle_handles)
                    for h, _ in pivots:
                        v = _verifications.get(h)
                        if v and v.overall_confidence < 0.3:
                            _unverified.add(h)
                except Exception as exc:
                    logger.debug("Handle verification skipped (non-fatal): %s", exc)

                for handle, confidence in pivots:
                    # Reduce confidence for handles that don't exist on any
                    # platform — they won't pass _initial_targets (>= 0.65)
                    if handle in _unverified:
                        confidence = 0.1
                    self._add_identifier(
                        result,
                        Identifier(
                            value=handle,
                            id_type=IdentifierType.USERNAME,
                            source="name_pivot",
                            confidence=confidence,
                        ),
                    )

        # Phase 1: scan raw target plus name-derived username pivots
        initial_targets = self._cap_targets(
            self._initial_targets(target, result),
        )

        logger.info("Deep scan starting: %s (%d initial targets)", target, len(initial_targets))
        await self._run_iteration(result, initial_targets)

        # Phase 2: Recursive scanning with discovered identifiers
        seen_targets: set[str] = {target.lower()}
        for iteration in range(1, self.max_iterations):
            if len(result.identifiers) >= self.max_identifiers:
                logger.info("Max identifiers reached (%d)", self.max_identifiers)
                break

            # Collect new identifiers to scan
            new_targets = self._cap_targets(self._get_new_targets(result, seen_targets))
            if not new_targets:
                logger.info("No new identifiers found at iteration %d — stopping", iteration)
                break

            logger.info("Iteration %d: scanning %d new identifiers", iteration, len(new_targets))
            result.iterations = iteration
            await self._run_iteration(result, new_targets)
            seen_targets.update(t.lower() for t in new_targets)

        result.completed_at = datetime.now(timezone.utc)

        # --- PHASE 3: External Tool Intelligence (Sherlock, Maigret, theHarvester) ---
        from src.modules.vendor.external_tools import ExternalToolIntel

        ext_intel = ExternalToolIntel()

        # Extract unique usernames and domains discovered during iterations
        usernames = list({i.value for i in result.identifiers if i.id_type == IdentifierType.USERNAME})

        # If no usernames were found directly, pivot the target name
        if not usernames and self._detect_identifier(target, "init").id_type == IdentifierType.NAME:
            from src.modules.deep_scan.name_pivots import primary_username_for_name

            p_uname = primary_username_for_name(target)
            if p_uname:
                usernames.append(p_uname)

        usernames = usernames[:3]  # Limit to 3 max
        domains = list({i.value for i in result.identifiers if i.id_type == IdentifierType.DOMAIN})[
            :2
        ]  # Limit to 2 max

        ext_tasks = []
        for uname in usernames:
            ext_tasks.append(ext_intel.scan_username(uname))
        for dom in domains:
            ext_tasks.append(ext_intel.scan_domain(dom))

        if ext_tasks:
            logger.info(
                "Executing Phase 3: %d External CLI Tasks (Sherlock/theHarvester)...",
                len(ext_tasks),
            )
            ext_results = await asyncio.gather(*ext_tasks, return_exceptions=True)
            for res in ext_results:
                if isinstance(res, ScanResult):
                    result.scan_results.append(res)
                    result.findings.extend(res.findings)

        # --- END PHASE 3 ---

        # --- PHASE 4: Profile Scraping & Vision Correlation Verification ---
        social_findings = [
            f for f in result.findings if f.module == "social_osint" and f.raw_data.get("type") == "social_account"
        ]
        if social_findings:
            logger.info(
                "Executing Phase 4: Scraping and correlating %d social profiles...",
                len(social_findings),
            )
            from src.modules.deep_scan.deep_scraper import DeepScraperEngine
            from src.modules.deep_scan.vision_correlator import VisionCorrelator

            scraper = DeepScraperEngine()
            correlator = VisionCorrelator()

            high_value_platforms = {
                "linkedin",
                "medium",
                "linktree",
                "strava",
                "github",
                "gitlab",
                "instagram",
                "tiktok",
            }
            to_verify = [f for f in social_findings if f.raw_data.get("platform") in high_value_platforms][:5]

            async def verify_finding(finding) -> None:
                url = finding.raw_data.get("url")
                if not url:
                    return
                try:
                    scraped = await scraper.scrape_profile(url)
                    if scraped:
                        finding.raw_data["bio"] = scraped.get("text_content", "")[:500]
                        finding.raw_data["profile_picture"] = scraped.get("profile_picture_url", "")

                        target_profile = {"text_content": f"Full Name: {target}"}
                        confidence = await correlator.correlate_profiles(target_profile, scraped)
                        finding.raw_data["correlation_confidence"] = confidence
                        finding.raw_data["verified"] = confidence >= 0.5
                        logger.info(
                            "Profile %s correlation confidence: %.2f (verified=%s)",
                            url,
                            confidence,
                            finding.raw_data["verified"],
                        )
                    else:
                        finding.raw_data["verified"] = False
                        finding.raw_data["correlation_confidence"] = 0.0
                except Exception as e:
                    logger.debug("Failed to scrape/correlate profile %s: %s", url, e)
                    finding.raw_data["verified"] = False
                    finding.raw_data["correlation_confidence"] = 0.0

            if to_verify:
                await asyncio.gather(*[verify_finding(f) for f in to_verify], return_exceptions=True)

            # Filter out unverified profiles to ensure we only report confirmed identities
            # Also deduplicate by URL to avoid showing the same profile multiple times
            verified_findings = []
            seen_urls = set()

            for f in result.findings:
                # If it went through verification and failed, drop it
                if "verified" in f.raw_data and not f.raw_data["verified"]:
                    continue

                # Deduplicate social profiles by URL
                url = f.raw_data.get("url")
                if url:
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                verified_findings.append(f)

            result.findings = verified_findings
        # --- END PHASE 4 ---

        # ZKIT cross-module correlation
        try:
            result.zkit_result = self._run_zkit_correlation(result)
        except Exception as exc:
            logger.warning("ZKIT correlation failed: %s", exc)
            result.errors.append(f"zkit_correlation: {exc}")

        logger.info(
            "Deep scan complete: %d identifiers, %d findings, %d iterations, %.1fs",
            result.identifier_count,
            result.finding_count,
            result.iterations,
            result.duration_sec,
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
        from src.cli.main import _get_module

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
                        if self._should_scan(mod_name, target):
                            tasks.append(self._scan_source_adapter(mod_name, source_inst, target, result))
                continue

            if mod_name in _FREE_INTEL_MODULES:
                # Free intel adapter path

                relevant_targets = self._filter_targets_for_module(mod_name, targets, result)
                if not relevant_targets:
                    continue

                for target in relevant_targets:
                    if self._should_scan(mod_name, target):
                        tasks.append(self._scan_free_intel_module(mod_name, target, result))
                continue

            mod = _get_module(mod_name)
            if not mod:
                continue

            # Filter targets relevant to this module
            relevant_targets = self._filter_targets_for_module(mod_name, targets, result)
            if not relevant_targets:
                continue

            for target in relevant_targets:
                if self._should_scan(mod_name, target):
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

    async def _run_module_scan(
        self,
        scan_coro: Awaitable[ScanResult],
        error_prefix: str,
        target: str,
        result: DeepScanResult,
    ) -> None:
        """Run a module scan through a common sem/timeout/error-handling pattern."""
        try:
            async with self._sem:
                scan_result = await asyncio.wait_for(
                    scan_coro,
                    timeout=self.timeout_per_module,
                )
            if isinstance(scan_result, ScanResult):
                result.scan_results.append(scan_result)
                for finding in scan_result.findings:
                    result.findings.append(finding)
        except asyncio.TimeoutError:
            result.errors.append(f"{error_prefix}({target}): timeout")
        except Exception as exc:
            result.errors.append(f"{error_prefix}({target}): {exc}")

    async def _scan_module(
        self,
        mod_name: str,
        mod: Any,
        target: str,
        result: DeepScanResult,
    ) -> None:
        """Run a single module scan."""
        scan_kwargs: dict[str, Any] = {}
        if mod_name == "people_finder":
            scan_kwargs["timeout"] = int(self.timeout_per_module)
        await self._run_module_scan(
            mod.scan(target, **scan_kwargs),
            mod_name,
            target,
            result,
        )

    async def _scan_source_adapter(
        self,
        source_name: str,
        source_inst: Any,
        target: str,
        result: DeepScanResult,
    ) -> None:
        """Run a breach/leak source via the source adapter."""
        from src.modules.deep_scan.source_adapter import run_source_scan

        await self._run_module_scan(
            run_source_scan(source_name, target, source_inst),
            f"source_{source_name}",
            target,
            result,
        )

    async def _scan_free_intel_module(
        self,
        mod_name: str,
        target: str,
        result: DeepScanResult,
    ) -> None:
        """Run a free intel module via the free_intel_adapter."""
        from src.modules.deep_scan.free_intel_adapter import run_free_intel_scan

        await self._run_module_scan(
            run_free_intel_scan(mod_name, target),
            f"free_{mod_name}",
            target,
            result,
        )

    def _get_new_targets(self, result: DeepScanResult, seen: set[str]) -> set[str]:
        """Extract new targets from discovered identifiers."""
        from src.modules.deep_scan.extractor import username_from_profile_url

        targets: set[str] = set()
        for ident in result.identifiers:
            if ident.confidence < 0.3:
                continue
            value = ident.value.strip()
            if ident.id_type == IdentifierType.SOCIAL_PROFILE and "://" in value:
                parsed = username_from_profile_url(value)
                if parsed:
                    value = parsed
                else:
                    continue
            if value.lower().startswith(("http://", "https://")):
                continue
            if value.lower() in seen:
                continue
            targets.add(value)
        return targets

    def _filter_targets_for_module(
        self,
        mod_name: str,
        targets: set[str],
        result: DeepScanResult,
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
            return list(self.modules)
        return list(_MODULE_INPUTS.keys())

    def _should_scan(self, mod_name: str, target: str) -> bool:
        """Skip duplicate module+target work within one scan."""
        key = (mod_name, target.strip().lower())
        if key in self._scanned_pairs:
            return False
        self._scanned_pairs.add(key)
        return True

    def _initial_targets(self, target: str, result: DeepScanResult) -> set[str]:
        out: set[str] = {target}
        for ident in result.identifiers:
            if ident.id_type == IdentifierType.USERNAME and ident.confidence >= 0.65:
                out.add(ident.value)
        return out

    def _cap_targets(self, targets: set[str]) -> set[str]:
        if len(targets) <= self.max_targets_per_iteration:
            return targets
        # Prefer emails and handles over raw display names
        ranked = sorted(
            targets,
            key=lambda t: (
                0 if "@" in t else 1,
                0 if " " not in t else 2,
                len(t),
            ),
        )
        return set(ranked[: self.max_targets_per_iteration])

    @staticmethod
    def _detect_identifier(value: str, source: str) -> Optional[Identifier]:
        """Auto-detect the type of an identifier."""
        import re

        value = value.strip()

        if not value:
            return None

        # Email
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            return Identifier(value=value.lower(), id_type=IdentifierType.EMAIL, source=source)

        # Phone
        if re.match(r"^[\+]?[0-9]{7,15}$", re.sub(r"[\s\-\.\(\)]", "", value)):
            return Identifier(value=value, id_type=IdentifierType.PHONE, source=source)

        # Ethereum address
        if re.match(r"^0x[0-9a-fA-F]{40}$", value):
            return Identifier(
                value=value,
                id_type=IdentifierType.CRYPTO_ADDRESS,
                source=source,
                metadata={"chain": "ethereum"},
            )

        # IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return Identifier(value=value, id_type=IdentifierType.IP, source=source)

        # Domain
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", value):
            return Identifier(value=value.lower(), id_type=IdentifierType.DOMAIN, source=source)

        # NIK (16 digits)
        if re.match(r"^\d{16}$", value):
            return Identifier(value=value, id_type=IdentifierType.NIK, source=source)

        # Default to username
        if re.match(r"^[a-zA-Z0-9_.-]{3,50}$", value):
            return Identifier(value=value, id_type=IdentifierType.USERNAME, source=source)

        # Default to name
        return Identifier(value=value, id_type=IdentifierType.NAME, source=source)
