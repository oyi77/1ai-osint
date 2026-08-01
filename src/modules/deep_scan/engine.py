"""Deep Scan Engine — Recursive identity investigation.

Core engine that orchestrates recursive scanning across all modules.
Each finding is parsed for new identifiers, which feed back as inputs
until no new identifiers are discovered.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from src.core.config import settings
from src.core.models import Finding, ScanResult, Severity
from src.core.rbac import AccessTier
from src.core.source_registry import can_run_keyless, transport_priority
from src.modules.deep_scan import (
    DeepScanResult,
    Identifier,
    IdentifierType,
)
from src.modules.deep_scan._module_config import (
    MODULE_INPUTS,
    SOURCE_MODULES,
)
from src.modules.deep_scan.deep_scraper import DeepScraperEngine
from src.modules.deep_scan.extractor import (
    _is_valid_nik,
    extract_identifiers,
    extract_usernames_from_profiles,
    username_from_profile_url,
)
from src.modules.deep_scan.free_intel_adapter import (
    list_free_intel_modules,
    run_free_intel_scan,
)
from src.modules.deep_scan.handle_verifier import batch_verify_handles
from src.modules.deep_scan.name_pivots import (
    primary_username_for_name,
    username_candidates_from_name,
)
from src.modules.deep_scan.profiles import fast_module_list, fast_scan_defaults
from src.modules.deep_scan.source_adapter import run_source_scan
from src.modules.deep_scan.vision_correlator import VisionCorrelator

logger = logging.getLogger(__name__)

# Module-level aliases for imported config
_MODULE_INPUTS = MODULE_INPUTS
_SOURCE_MODULES = SOURCE_MODULES

_FREE_INTEL_MODULES: set[str] = set(list_free_intel_modules())


class DeepScanEngine:
    """Recursive identity investigation engine.

    Takes an initial identifier and recursively discovers all connected
    identifiers across all modules until no new identifiers are found.
    """

    def __init__(
        self,
        max_iterations: int | None = None,
        max_identifiers: int = 500,
        timeout_per_module: float | None = None,
        modules: list[str] | None = None,
        *,
        fast: bool = False,
        max_concurrency: int = 24,
        max_pivot_handles: int = 5,
        budget: float = 5.0,
        max_targets_per_iteration: int = 25,
        profile_config: Any = None,
        requester_tier: AccessTier = AccessTier.ADMIN,
        no_api: bool | None = None,
    ):
        if profile_config is not None:
            # Profile supplies the defaults; explicit caller values are honored
            # but capped at the profile limit (so `--max-iterations 0` can seed-only).
            max_iterations = (
                profile_config.max_iterations
                if max_iterations is None
                else min(max_iterations, profile_config.max_iterations)
            )
            timeout_per_module = (
                profile_config.timeout_per_module
                if timeout_per_module is None
                else min(timeout_per_module, profile_config.timeout_per_module)
            )
            max_identifiers = profile_config.max_identifiers
            max_pivot_handles = profile_config.max_pivot_handles
            max_targets_per_iteration = profile_config.max_targets_per_iteration
            max_concurrency = profile_config.max_concurrency
            fast = profile_config.fast_mode
            modules = list(profile_config.modules)
        elif fast:
            defaults = fast_scan_defaults()
            max_iterations = (
                int(defaults["max_iterations"])
                if max_iterations is None
                else min(max_iterations, int(defaults["max_iterations"]))
            )
            timeout_per_module = (
                float(defaults["timeout_per_module"])
                if timeout_per_module is None
                else min(timeout_per_module, float(defaults["timeout_per_module"]))
            )
            max_identifiers = min(max_identifiers, int(defaults["max_identifiers"]))
            max_pivot_handles = int(defaults["max_pivot_handles"])
            max_targets_per_iteration = int(defaults["max_targets_per_iteration"])
            max_concurrency = int(defaults["max_concurrency"])
            if modules is None:
                modules = fast_module_list()

        # No profile and no fast path: fall back to plain defaults.
        self.max_iterations = max_iterations if max_iterations is not None else 10
        self.max_identifiers = max_identifiers
        self.timeout_per_module = timeout_per_module if timeout_per_module is not None else 60.0
        self.modules = set(modules) if modules else set(_MODULE_INPUTS.keys())
        self.fast = fast
        self.max_concurrency = max_concurrency
        self.max_pivot_handles = max_pivot_handles
        self.budget = budget
        self.max_targets_per_iteration = max_targets_per_iteration
        self.requester_tier = requester_tier
        self.no_api = settings.no_api if no_api is None else no_api
        self._sem = asyncio.Semaphore(max_concurrency)
        self._scanned_pairs: set[tuple[str, str]] = set()

    async def scan(self, target: str) -> DeepScanResult:
        """Run a deep scan on a target identifier."""
        # Fire the on_scan_start hook (error-isolated: a failing plugin never
        # aborts the scan itself).
        try:
            from src.plugin import get_dispatcher

            await get_dispatcher().dispatch(
                "on_scan_start",
                target=target,
                module="deep_scan",
            )
        except Exception as exc:  # pragma: no cover - defensive only
            logger.warning("Plugin hook on_scan_start failed: %s", exc)

        started_at = datetime.now(timezone.utc)
        result = DeepScanResult(
            target=target,
            started_at=started_at,
            max_iterations=self.max_iterations,
        )

        try:
            return await self._scan_impl(target, result, started_at)
        except Exception as exc:
            logger.exception("Deep scan failed for %s", target)
            result.errors.append(f"deep_scan: {exc}")
            result.completed_at = datetime.now(timezone.utc)
            # Fire the on_error hook — plugins may record or alert on failure.
            try:
                from src.plugin import get_dispatcher

                await get_dispatcher().dispatch(
                    "on_error",
                    error=exc,
                    context={"target": target, "module": "deep_scan"},
                )
            except Exception as hook_exc:  # pragma: no cover - defensive only
                logger.warning("Plugin hook on_error failed: %s", hook_exc)
            return result

    async def _scan_impl(
        self,
        target: str,
        result: DeepScanResult,
        started_at: datetime,
    ) -> DeepScanResult:
        """Inner scan body — hook-free so plugins can't corrupt the flow."""

        # Detect initial identifier type
        initial = self._detect_identifier(target, "input")
        if initial:
            result.identifiers.append(initial)
            if initial.id_type == IdentifierType.NAME:
                pivots = username_candidates_from_name(target)[: self.max_pivot_handles]

                # Verify handle existence before trusting name-permuted handles.
                # This prevents the misattribution bug where a handle derived from
                # a name (e.g. "izzuddinfikri" from "Fikri Izzuddin") gets scanned
                # even though it belongs to a different person.
                _unverified: set[str] = set()
                try:
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

        # Phase 3: External Tool Intelligence
        await self._run_external_tools_phase(target, result)

        # Phase 4: Profile Scraping & Vision Correlation
        await self._verify_profiles_phase(target, result)

        # Phase 5: AI snippet enrichment — structured dossier from dork snippets
        try:
            await self._run_ai_enrichment(result, target)
        except Exception as exc:
            logger.warning("AI enrichment failed: %s", exc)
            result.errors.append(f"ai_enricher: {exc}")

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

        self._dedup_findings(result)

        # Fire the on_scan_end hook (error-isolated). Plugins may observe the
        # final result; the scan outcome is unaffected.
        try:
            from src.plugin import get_dispatcher

            await get_dispatcher().dispatch("on_scan_end", result=result)
        except Exception as exc:  # pragma: no cover - defensive only
            logger.warning("Plugin hook on_scan_end failed: %s", exc)

        return result

    async def _run_ai_enrichment(self, result: DeepScanResult, target: str) -> None:
        """Phase 5: synthesize a structured dossier from search snippets.

        Collects snippets from free-intel dork findings (raw_data["snippet"] or
        raw_data["snippets"]), then runs the AI extractor once over them. A
        non-empty dossier is attached as an ``ai_enricher`` finding so it
        surfaces in the final report. Skipped entirely when the extractor is
        unavailable (no OPENAI_API_KEY / OMNIROUTE_API_KEY) or yields nothing.
        """
        snippets: list[str] = []
        for finding in result.findings:
            raw = finding.raw_data or {}
            for key in ("snippet", "snippets"):
                value = raw.get(key)
                if isinstance(value, str):
                    snippets.append(value)
                elif isinstance(value, list):
                    snippets.extend(s for s in value if isinstance(s, str))
        if not snippets:
            return

        from src.modules.free_intel.ai_enricher import AIExtractor

        extractor = AIExtractor()
        if not extractor.is_available():
            logger.debug("ai_enricher skipped: no API key configured")
            return

        dossier = await asyncio.wait_for(
            extractor.extract_from_snippets(target, snippets[:40]),
            timeout=60,
        )
        if not dossier:
            return
        serialized = dossier.model_dump(exclude_defaults=True)
        if not serialized:
            logger.debug("ai_enricher skipped: empty dossier")
            return

        result.findings.append(
            Finding(
                id=f"find-ai_enricher-{len(result.findings) + 1}",
                module="ai_enricher",
                title=f"AI dossier for {target}",
                description=(f"Structured profile synthesized from search snippets ({len(snippets)} snippets)"),
                severity=Severity.INFO,
                raw_data={
                    "dossier": serialized,
                    "snippet_count": len(snippets),
                    "target": target,
                },
                confidence=0.6,
                tags=["ai", "enrichment", "dossier"],
            )
        )

    async def _run_external_tools_phase(self, target: str, result: DeepScanResult) -> None:
        """Phase 3: Run external OSINT tools (Sherlock, theHarvester, etc.) on discovered usernames and domains.

        Collects unique usernames and domains from the scan results so far,
        then dispatches external CLI-based intelligence tools to gather
        additional cross-platform profile and domain information.
        """
        from src.modules.vendor.external_tools import ExternalToolIntel

        ext_intel = ExternalToolIntel()

        # Extract unique usernames and domains discovered during iterations
        usernames = list({i.value for i in result.identifiers if i.id_type == IdentifierType.USERNAME})

        # If no usernames were found directly, pivot the target name
        init_ident = self._detect_identifier(target, "init")
        if not usernames and init_ident is not None and init_ident.id_type == IdentifierType.NAME:
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
                elif isinstance(res, Exception):
                    logger.warning("External tool phase error: %s", res)

    async def _verify_profiles_phase(self, target: str, result: DeepScanResult) -> None:
        """Phase 4: Scrape social profiles and run vision-based correlation to verify identity.

        Filters social OSINT findings for high-value platforms, scrapes each
        profile for bio and picture content, then uses the VisionCorrelator to
        cross-check against the target name. Unverified or duplicate profiles
        are filtered out from the final findings list.
        """
        social_findings = [
            f
            for f in result.findings
            if f.module == "social_osint" and f.raw_data and f.raw_data.get("type") == "social_account"
        ]
        if not social_findings:
            return

        logger.info(
            "Executing Phase 4: Scraping and correlating %d social profiles...",
            len(social_findings),
        )
        scraper = DeepScraperEngine(cache_dir=str(settings.cache_path))
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
        to_verify = [f for f in social_findings if f.raw_data and f.raw_data.get("platform") in high_value_platforms][
            :5
        ]

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
            raw_data = f.raw_data or {}
            # If it went through verification and failed, drop it
            if "verified" in raw_data and not raw_data["verified"]:
                continue

            # Deduplicate social profiles by URL
            url = raw_data.get("url")
            if url:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

            verified_findings.append(f)

        result.findings = verified_findings

    def _run_zkit_correlation(self, result: DeepScanResult) -> Any | None:
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
        from src.cli.helpers import get_module as _get_module

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
        scan_factory: Callable[[], Awaitable[ScanResult | None]],
        error_prefix: str,
        mod_name: str,
        target: str,
        result: DeepScanResult,
        *,
        retry_none: bool = True,
    ) -> None:
        """Run a module scan through a common sem/timeout/retry/error pattern.

        ``scan_factory`` returns a fresh coroutine per attempt so retries are
        possible. Transient failures (timeout, connection errors, HTTP 429) and None
        results retry up to 3 times with exponential backoff; a pair
        that still fails is dropped and marked so it is not re-proposed in
        later iterations. Permanent failures are logged, recorded and marked
        once.

        ``retry_none`` controls whether a ``None`` result is treated as a
        transient failure to retry or as a definitive empty answer. Source
        adapters and free-intel modules already return None as a stable
        terminal state (their adapters decide what counts as empty), so they
        pass ``retry_none=False`` — an empty result is recorded and the pair
        is never re-proposed, without polluting the error list.
        """

        def _is_transient(exc: BaseException) -> bool:
            if isinstance(exc, (asyncio.TimeoutError, ConnectionError, TimeoutError)):
                return True
            # HTTP 429 (rate limit) is transient by nature — docstring below.
            return getattr(exc, "status", None) == 429

        for attempt in range(1, 4):
            try:
                async with self._sem:
                    scan_result = await asyncio.wait_for(
                        scan_factory(),
                        timeout=self.timeout_per_module,
                    )
                if scan_result is None:
                    if not retry_none:
                        # Definitive empty — mark once so later iterations do
                        # not re-propose the pair; no error is recorded.
                        logger.debug("Module %s on %s returned empty (definitive)", error_prefix, target)
                        self._mark_scanned(mod_name, target)
                        return
                    if attempt < 3:
                        logger.warning(
                            "No result for %s on %s (attempt %d/3)",
                            error_prefix,
                            target,
                            attempt,
                        )
                        await asyncio.sleep(2 ** (attempt - 1))
                        continue
                    logger.warning(
                        "Module %s on %s returned no result after 3 attempts",
                        error_prefix,
                        target,
                    )
                    result.errors.append(f"{error_prefix}({target}): no result after 3 attempts")
                    self._mark_scanned(mod_name, target)
                    return
                if isinstance(scan_result, ScanResult):
                    result.scan_results.append(scan_result)
                    for finding in scan_result.findings:
                        result.findings.append(finding)
                self._mark_scanned(mod_name, target)
                return
            except Exception as exc:
                if _is_transient(exc):
                    if attempt < 3:
                        logger.warning(
                            "Transient failure for %s on %s (attempt %d/3): %s",
                            error_prefix,
                            target,
                            attempt,
                            exc,
                        )
                        await asyncio.sleep(2 ** (attempt - 1))
                        continue
                    # Ran out of retries — drop the pair and mark it so
                    # seen-targets/new-target discovery don't re-propose it.
                    logger.warning(
                        "Module %s on %s failed after 3 attempts: %s",
                        error_prefix,
                        target,
                        exc,
                    )
                    if isinstance(exc, asyncio.TimeoutError):
                        result.errors.append(f"{error_prefix}({target}): timeout after 3 attempts")
                    else:
                        result.errors.append(f"{error_prefix}({target}): {exc}")
                    self._mark_scanned(mod_name, target)
                    return
                # Permanent failure — record once and mark so we don't loop.
                logger.warning("Module %s failed permanently for %s: %s", error_prefix, target, exc)
                result.errors.append(f"{error_prefix}({target}): {exc}")
                self._mark_scanned(mod_name, target)
                return

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
            lambda: mod.scan(target, **scan_kwargs),
            mod_name,
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
        await self._run_module_scan(
            lambda: run_source_scan(
                source_name,
                target,
                source_inst,
                requester="deep_scan_engine",
                requester_tier=self.requester_tier,
            ),
            f"source_{source_name}",
            source_name,
            target,
            result,
            retry_none=False,
        )

    async def _scan_free_intel_module(
        self,
        mod_name: str,
        target: str,
        result: DeepScanResult,
    ) -> None:
        """Run a free intel module via the free_intel_adapter."""
        await self._run_module_scan(
            lambda: run_free_intel_scan(
                mod_name, target, requester="deep_scan_engine", requester_tier=self.requester_tier
            ),
            f"free_{mod_name}",
            mod_name,
            target,
            result,
            retry_none=False,
        )

    def _get_new_targets(self, result: DeepScanResult, seen: set[str]) -> set[str]:
        """Extract new targets from discovered identifiers."""
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
        """Get list of modules to use, RE-first when 0-API mode is enabled.

        In 0-API mode the list is filtered to keyless-capable transports and
        stably sorted by transport priority so reverse-engineered/keyless
        sources run before API-keyed ones.
        """
        mods = list(self.modules) if self.modules else list(_MODULE_INPUTS.keys())
        if self.no_api:
            mods = [m for m in mods if can_run_keyless(m)]
            mods.sort(key=transport_priority)
        return mods

    def _should_scan(self, mod_name: str, target: str) -> bool:
        """Return whether this module+target pair still needs scanning.

        Pure check — marking happens in ``_run_module_scan`` once the scan
        succeeds or fails permanently; transient failures are retried within
        ``_run_module_scan``'s bounded retry loop instead of being re-proposed
        in later iterations.
        """
        key = (mod_name, target.strip().lower())
        return key not in self._scanned_pairs

    def _mark_scanned(self, mod_name: str, target: str) -> None:
        """Record a successfully (or permanently) processed module+target pair."""
        self._scanned_pairs.add((mod_name, target.strip().lower()))

    @staticmethod
    def _dedup_findings(result: DeepScanResult) -> None:
        """Collapse duplicate findings (same module + entity type + value + location).

        Keeps the first occurrence and merges severity (highest wins),
        confidence (max) and tags.
        """
        severity_rank = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        seen: dict[tuple[str, str, str, str], Finding] = {}
        for finding in result.findings:
            raw = finding.raw_data or {}
            type_: str = "title"
            value: str = finding.title.lower()
            for field in ("email", "username", "phone", "nik", "domain", "ip_address", "crypto_address"):
                v = raw.get(field)
                if isinstance(v, str) and v:
                    type_ = field
                    value = v.lower()
                    break
            loc_parts = []
            for loc_field in ("path", "line", "url"):
                v = raw.get(loc_field)
                if v is not None:
                    loc_parts.append(str(v))
                    break
            loc = loc_parts[0] if loc_parts else ""
            key = (finding.module, type_, value, loc)
            prev = seen.get(key)
            if prev is None:
                seen[key] = finding
                continue
            if severity_rank.get(finding.severity, 0) > severity_rank.get(prev.severity, 0):
                prev.severity = finding.severity
            if finding.confidence and finding.confidence > (prev.confidence or 0):
                prev.confidence = finding.confidence
            for tag in finding.tags or []:
                if tag not in (prev.tags or []):
                    prev.tags.append(tag)
        result.findings = list(seen.values())

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
    def _detect_identifier(value: str, source: str) -> Identifier | None:
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

        # Bitcoin address
        if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", value):
            return Identifier(
                value=value,
                id_type=IdentifierType.CRYPTO_ADDRESS,
                source=source,
                metadata={"chain": "bitcoin"},
            )

        # IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return Identifier(value=value, id_type=IdentifierType.IP, source=source)

        # Domain
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", value):
            return Identifier(value=value.lower(), id_type=IdentifierType.DOMAIN, source=source)

        # NIK (16 digits, structurally valid province/city digits)
        if re.match(r"^\d{16}$", value) and _is_valid_nik(value):
            return Identifier(value=value, id_type=IdentifierType.NIK, source=source)

        # Default to username
        if re.match(r"^[a-zA-Z0-9_.-]{3,50}$", value):
            return Identifier(value=value, id_type=IdentifierType.USERNAME, source=source)

        # Default to name
        return Identifier(value=value, id_type=IdentifierType.NAME, source=source)
