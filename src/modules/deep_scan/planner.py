"""LangGraph planner for budget-aware module scheduling in deep scans."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, List, Tuple

from langgraph.graph import END, StateGraph

from src.modules.deep_scan import (
    DeepScanResult,
    Identifier,
    IdentifierType,
)
from src.modules.deep_scan.extractor import (
    extract_identifiers,
    extract_usernames_from_profiles,
)

logger = logging.getLogger(__name__)

# Predefined costs for each deep scan module
MODULE_COSTS: dict[str, float] = {
    "dehashed": 5.0,
    "intelx": 5.0,
    "snusbase": 4.0,
    "hibp": 3.0,
    "leakcheck": 3.0,
    "snylla": 3.0,
    "vuln_scanner": 2.0,
    "social_osint": 1.0,
    "people_finder": 1.0,
    "phone_finder": 1.0,
    "data_leaks": 1.0,
    "crypto_balance": 1.0,
    "crypto_tracer": 1.0,
    "domain_recon": 1.0,
    "gitleaks": 1.0,
    "email_osint": 1.0,
}


def get_module_cost(name: str) -> float:
    """Get the cost of a module, defaulting to 1.0."""
    return MODULE_COSTS.get(name.lower(), 1.0)


class DeepScanPlanner:
    """LangGraph planner for orchestrating deep scan modules under budget constraints."""

    def __init__(self, engine: Any, budget: float = 15.0):
        self.engine = engine
        self.budget = budget
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Create the LangGraph StateGraph workflow."""
        workflow = StateGraph(dict)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("schedule_iteration", self.schedule_iteration)
        workflow.add_node("execute_tasks", self.execute_tasks)

        workflow.set_entry_point("initialize")
        workflow.add_edge("initialize", "schedule_iteration")
        workflow.add_edge("schedule_iteration", "execute_tasks")

        # After execution, route conditionally based on budget and iterations
        workflow.add_conditional_edges(
            "execute_tasks",
            self.should_continue,
            {
                "continue": "schedule_iteration",
                "end": END,
            },
        )

        return workflow.compile()

    async def run(self, target: str) -> DeepScanResult:
        """Execute the LangGraph planner for the deep scan."""
        started_at = datetime.now(timezone.utc)

        # Build initial state
        initial_state = {
            "target": target,
            "remaining_budget": self.budget,
            "iterations": 0,
            "max_iterations": self.engine.max_iterations,
            "identifiers": [],
            "findings": [],
            "scan_results": [],
            "errors": [],
            "scanned_pairs": set(),
            "next_tasks": [],
            "seen_targets": {target.lower()},
            "completed": False,
        }

        # Run state machine
        final_state = await self.graph.ainvoke(initial_state)

        # Map back to DeepScanResult
        result = DeepScanResult(
            target=target,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            identifiers=final_state["identifiers"],
            findings=final_state["findings"],
            scan_results=final_state["scan_results"],
            iterations=final_state["iterations"],
            max_iterations=self.engine.max_iterations,
            errors=final_state["errors"],
        )
        return result

    async def initialize(self, state: dict) -> dict:
        """Node: Initialize identifiers list and initial target candidates."""
        target = state["target"]
        initial_id = self.engine._detect_identifier(target, "input")
        if initial_id:
            state["identifiers"].append(initial_id)
            if initial_id.id_type == IdentifierType.NAME:
                from src.modules.deep_scan.name_pivots import (
                    username_candidates_from_name,
                )

                pivots = username_candidates_from_name(target)[
                    : self.engine.max_pivot_handles
                ]
                for handle, confidence in pivots:
                    ident = Identifier(
                        value=handle,
                        id_type=IdentifierType.USERNAME,
                        source="name_pivot",
                        confidence=confidence,
                    )
                    self.engine._add_identifier(
                        DeepScanResult(
                            target=target,
                            started_at=datetime.now(timezone.utc),
                            identifiers=state["identifiers"],
                        ),
                        ident,
                    )

                # Phase 10: Deep Identity Pivot (Social Dorks & Tech Jobs)
                try:
                    from src.modules.free_intel.social_dorks_intel import (
                        SocialDorksIntel,
                    )
                    from src.modules.free_intel.tech_jobs_intel import TechJobsIntel

                    social = SocialDorksIntel()
                    tech = TechJobsIntel()

                    import asyncio

                    social_res, tech_res = await asyncio.gather(
                        social.search(target),
                        tech.search(target),
                        return_exceptions=True,
                    )

                    for res_list in [social_res, tech_res]:
                        if isinstance(res_list, list):
                            for r in res_list:
                                handle = getattr(r, "username", "")
                                if not handle and hasattr(r, "url"):
                                    handle = r.url.rstrip("/").split("/")[-1]
                                if handle and handle not in [
                                    i.value for i in state["identifiers"]
                                ]:
                                    self.engine._add_identifier(
                                        DeepScanResult(
                                            target=target,
                                            started_at=datetime.now(timezone.utc),
                                            identifiers=state["identifiers"],
                                        ),
                                        Identifier(
                                            value=handle,
                                            id_type=IdentifierType.USERNAME,
                                            source="deep_dork_pivot",
                                            confidence=0.8,
                                        ),
                                    )
                except Exception as e:
                    import logging

                    logging.getLogger(__name__).warning("Phase 10 pivot failed: %s", e)

        return state

    def schedule_iteration(self, state: dict) -> dict:
        """Node: Determine module tasks to run that fit within the remaining budget."""
        remaining_budget = state["remaining_budget"]
        scanned_pairs = state["scanned_pairs"]
        seen_targets = state["seen_targets"]
        identifiers = state["identifiers"]

        # 1. Determine targets for this iteration
        if state["iterations"] == 0:
            # First pass: use target + derived username pivots
            current_targets = self.engine._initial_targets(
                state["target"],
                DeepScanResult(
                    target=state["target"],
                    started_at=datetime.now(timezone.utc),
                    identifiers=identifiers,
                ),
            )
        else:
            # Subsequent passes: use all discovered targets that haven't been processed yet
            current_targets = self.engine._get_new_targets(
                DeepScanResult(
                    target=state["target"],
                    started_at=datetime.now(timezone.utc),
                    identifiers=identifiers,
                ),
                seen_targets,
            )

        current_targets = self.engine._cap_targets(current_targets)
        if not current_targets:
            state["next_tasks"] = []
            return state

        # 2. Build candidate tasks (module_name, target_value)
        candidates: List[
            Tuple[str, str, float, float]
        ] = []  # (module_name, target_value, confidence, cost)
        active_modules = self.engine._get_active_modules()

        for mod_name in active_modules:
            relevant_targets = self.engine._filter_targets_for_module(
                mod_name,
                current_targets,
                DeepScanResult(
                    target=state["target"],
                    started_at=datetime.now(timezone.utc),
                    identifiers=identifiers,
                ),
            )
            for target in relevant_targets:
                # Avoid duplicate module-target scans
                key = (mod_name, target.strip().lower())
                if key in scanned_pairs:
                    continue

                # Retrieve target confidence
                confidence = 1.0
                for ident in identifiers:
                    if ident.value.strip().lower() == target.strip().lower():
                        confidence = ident.confidence
                        break

                cost = get_module_cost(mod_name)
                candidates.append((mod_name, target, confidence, cost))

        # 3. Sort candidates: high confidence first, then lower cost first
        candidates.sort(key=lambda x: (-x[2], x[3]))

        # 4. Fill schedule within budget
        next_tasks = []
        budget_temp = remaining_budget
        for mod_name, target, conf, cost in candidates:
            if budget_temp >= cost:
                budget_temp -= cost
                next_tasks.append((mod_name, target))
                scanned_pairs.add((mod_name, target.strip().lower()))
            else:
                logger.info(
                    "Skipping task %s on %s: cost %.1f exceeds remaining budget %.1f",
                    mod_name,
                    target,
                    cost,
                    budget_temp,
                )

        state["next_tasks"] = next_tasks
        state["remaining_budget"] = budget_temp

        # Add scheduled targets to seen_targets
        for _, tgt in next_tasks:
            seen_targets.add(tgt.lower())

        return state

    async def execute_tasks(self, state: dict) -> dict:
        """Node: Concurrently run all scheduled tasks for this iteration."""
        next_tasks = state["next_tasks"]
        if not next_tasks:
            return state

        result_mock = DeepScanResult(
            target=state["target"],
            started_at=datetime.now(timezone.utc),
            identifiers=state["identifiers"],
            findings=state["findings"],
            scan_results=state["scan_results"],
            errors=state["errors"],
        )

        tasks = []
        from src.cli.main import _get_module
        from src.modules.sources import discover_sources

        for mod_name, target in next_tasks:
            logger.info(
                "Executing %s on %s (Remaining Budget: %.1f)",
                mod_name,
                target,
                state["remaining_budget"],
            )
            from src.modules.deep_scan.engine import _SOURCE_MODULES

            if mod_name in _SOURCE_MODULES:
                all_sources = discover_sources()
                source_cls = all_sources.get(mod_name)
                if source_cls:
                    source_inst = source_cls()
                    tasks.append(
                        self.engine._scan_source_adapter(
                            mod_name, source_inst, target, result_mock
                        )
                    )
            else:
                mod = _get_module(mod_name)
                if mod:
                    tasks.append(
                        self.engine._scan_module(mod_name, mod, target, result_mock)
                    )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Extract new identifiers from all findings
        for finding in result_mock.findings:
            raw = finding.raw_data or {}
            text = str(raw)
            new_ids = extract_identifiers(text, finding.module)
            for nid in new_ids:
                self.engine._add_identifier(result_mock, nid)

        # Extract usernames from social media profiles
        profile_ids = extract_usernames_from_profiles(result_mock.findings)
        for pid in profile_ids:
            self.engine._add_identifier(result_mock, pid)

        state["iterations"] += 1
        return state

    def should_continue(self, state: dict) -> str:
        """Conditional routing: determine if we should stop or run another pass."""
        remaining_budget = state["remaining_budget"]
        iterations = state["iterations"]
        max_iterations = state["max_iterations"]
        next_tasks = state["next_tasks"]

        # Stop if no tasks were scheduled, budget exhausted, or max iterations hit
        if not next_tasks or remaining_budget <= 0.0 or iterations >= max_iterations:
            logger.info(
                "Deep scan planner complete: iterations=%d, remaining_budget=%.1f",
                iterations,
                remaining_budget,
            )
            return "end"
        return "continue"
