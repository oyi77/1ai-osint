"""Unit tests for the LangGraph-based deep scan budget-aware planner."""

from __future__ import annotations
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


from src.core.models import Finding
from src.modules.deep_scan import Identifier, IdentifierType, DeepScanResult
from src.modules.deep_scan.engine import DeepScanEngine
from src.modules.deep_scan.planner import DeepScanPlanner, get_module_cost


def test_get_module_cost():
    assert get_module_cost("dehashed") == 5.0
    assert get_module_cost("intelx") == 5.0
    assert get_module_cost("hibp") == 3.0
    assert get_module_cost("social_osint") == 1.0
    assert get_module_cost("unknown_module") == 1.0


@pytest.mark.asyncio
async def test_planner_initialization():
    engine = DeepScanEngine(budget=10.0, max_iterations=3)
    planner = DeepScanPlanner(engine, budget=10.0)

    state = {
        "target": "John Doe",
        "identifiers": [],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 10.0,
    }

    new_state = await planner.initialize(state)
    assert len(new_state["identifiers"]) >= 1
    assert new_state["identifiers"][0].id_type == IdentifierType.NAME
    assert new_state["identifiers"][0].value == "John Doe"


@pytest.mark.asyncio
async def test_planner_scheduling_within_budget():
    engine = DeepScanEngine(budget=5.0, max_iterations=3)
    # Enable a few mock modules
    engine._get_active_modules = MagicMock(
        return_value=["dehashed", "social_osint", "phone_finder"]
    )
    engine._filter_targets_for_module = MagicMock(return_value={"john_doe"})

    planner = DeepScanPlanner(engine, budget=5.0)

    state = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            )
        ],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 5.0,
        "scanned_pairs": set(),
        "seen_targets": {"john_doe"},
        "next_tasks": [],
    }

    # dehashed cost is 5.0, social_osint is 1.0, phone_finder is 1.0
    # The sorted candidates will be social_osint (cost 1), phone_finder (cost 1), dehashed (cost 5)
    # With budget 5.0, it should schedule both social_osint and phone_finder (sum cost 2), and skip dehashed (cost 5)
    new_state = planner.schedule_iteration(state)
    assert len(new_state["next_tasks"]) == 2
    assert ("social_osint", "john_doe") in new_state["next_tasks"]
    assert ("phone_finder", "john_doe") in new_state["next_tasks"]
    assert new_state["remaining_budget"] == 3.0


@pytest.mark.asyncio
async def test_planner_scheduling_skips_expensive():
    engine = DeepScanEngine(budget=3.0, max_iterations=3)
    engine._get_active_modules = MagicMock(return_value=["dehashed", "social_osint"])
    engine._filter_targets_for_module = MagicMock(return_value={"john_doe"})

    planner = DeepScanPlanner(engine, budget=3.0)

    state = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            )
        ],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 3.0,
        "scanned_pairs": set(),
        "seen_targets": {"john_doe"},
        "next_tasks": [],
    }

    # dehashed cost is 5.0 (does not fit in 3.0), social_osint is 1.0 (fits)
    # It should skip dehashed and schedule social_osint.
    new_state = planner.schedule_iteration(state)
    assert len(new_state["next_tasks"]) == 1
    assert new_state["next_tasks"][0] == ("social_osint", "john_doe")
    assert new_state["remaining_budget"] == 2.0


@pytest.mark.asyncio
async def test_planner_execute_tasks_integration():
    engine = DeepScanEngine(budget=10.0, max_iterations=3)
    planner = DeepScanPlanner(engine, budget=10.0)

    mock_scan_module = AsyncMock()
    engine._scan_module = mock_scan_module

    state = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            )
        ],
        "findings": [],
        "scan_results": [],
        "errors": [],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "next_tasks": [("social_osint", "john_doe")],
    }

    new_state = await planner.execute_tasks(state)
    assert mock_scan_module.called
    assert new_state["iterations"] == 1


def test_planner_should_continue():
    engine = DeepScanEngine(budget=10.0, max_iterations=3)
    planner = DeepScanPlanner(engine, budget=10.0)

    # Continue when tasks scheduled, budget remaining, iterations < max
    assert (
        planner.should_continue(
            {
                "remaining_budget": 5.0,
                "iterations": 1,
                "max_iterations": 3,
                "next_tasks": [("social_osint", "john")],
            }
        )
        == "continue"
    )

    # End if no next tasks
    assert (
        planner.should_continue(
            {
                "remaining_budget": 5.0,
                "iterations": 1,
                "max_iterations": 3,
                "next_tasks": [],
            }
        )
        == "end"
    )

    # End if budget exhausted
    assert (
        planner.should_continue(
            {
                "remaining_budget": 0.0,
                "iterations": 1,
                "max_iterations": 3,
                "next_tasks": [("social_osint", "john")],
            }
        )
        == "end"
    )

    # End if max iterations reached
    assert (
        planner.should_continue(
            {
                "remaining_budget": 5.0,
                "iterations": 3,
                "max_iterations": 3,
                "next_tasks": [("social_osint", "john")],
            }
        )
        == "end"
    )


@pytest.mark.asyncio
async def test_planner_edge_cases():
    engine = DeepScanEngine(budget=10.0, max_iterations=3)

    # 1. schedule_iteration with iterations > 0
    engine._get_new_targets = MagicMock(return_value={"new_target@email.com"})
    engine._cap_targets = MagicMock(side_effect=lambda x: x)
    engine._get_active_modules = MagicMock(return_value=["social_osint"])
    engine._filter_targets_for_module = MagicMock(return_value={"new_target@email.com"})

    planner = DeepScanPlanner(engine, budget=10.0)

    state = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            ),
            Identifier(
                value="new_target@email.com",
                id_type=IdentifierType.EMAIL,
                source="finding",
                confidence=0.8,
            ),
        ],
        "iterations": 1,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "scanned_pairs": set(),
        "seen_targets": {"john_doe"},
        "next_tasks": [],
    }

    new_state = planner.schedule_iteration(state)
    assert len(new_state["next_tasks"]) == 1
    assert new_state["next_tasks"][0] == ("social_osint", "new_target@email.com")

    # 2. schedule_iteration with no targets left
    state_no_targets = {
        "target": "john_doe",
        "identifiers": [],
        "iterations": 1,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "scanned_pairs": set(),
        "seen_targets": {"john_doe"},
        "next_tasks": [],
    }
    engine._get_new_targets = MagicMock(return_value=set())
    new_state_no_targets = planner.schedule_iteration(state_no_targets)
    assert new_state_no_targets["next_tasks"] == []

    # 3. schedule_iteration with duplicate targets in scanned_pairs
    state_duplicate = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            )
        ],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "scanned_pairs": {("social_osint", "john_doe")},
        "seen_targets": {"john_doe"},
        "next_tasks": [],
    }
    engine._initial_targets = MagicMock(return_value={"john_doe"})
    engine._get_active_modules = MagicMock(return_value=["social_osint"])
    engine._filter_targets_for_module = MagicMock(return_value={"john_doe"})
    new_state_duplicate = planner.schedule_iteration(state_duplicate)
    assert new_state_duplicate["next_tasks"] == []

    # 4. execute_tasks with empty next_tasks
    state_empty_tasks = {
        "target": "john_doe",
        "identifiers": [],
        "findings": [],
        "scan_results": [],
        "errors": [],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "next_tasks": [],
    }
    result_empty = await planner.execute_tasks(state_empty_tasks)
    assert result_empty == state_empty_tasks

    # 5. execute_tasks with source module
    state_source_task = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            )
        ],
        "findings": [],
        "scan_results": [],
        "errors": [],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "next_tasks": [("dehashed", "john_doe")],
    }

    mock_scan_source_adapter = AsyncMock()
    engine._scan_source_adapter = mock_scan_source_adapter

    with patch("src.modules.sources.discover_sources") as mock_discover:
        mock_source_cls = MagicMock()
        mock_discover.return_value = {"dehashed": mock_source_cls}
        await planner.execute_tasks(state_source_task)
        assert mock_scan_source_adapter.called


@pytest.mark.asyncio
async def test_planner_findings_extraction():
    engine = DeepScanEngine(budget=10.0, max_iterations=3)
    planner = DeepScanPlanner(engine, budget=10.0)

    async def mock_scan(mod_name, mod, target, result):
        result.findings.append(
            Finding(
                id="test-finding-1",
                title="Discovered social profile",
                module="social_osint",
                raw_data={
                    "username": "john_doe_discovered",
                    "email": "john@discovered.com",
                },
            )
        )

    engine._scan_module = mock_scan

    state = {
        "target": "john_doe",
        "identifiers": [
            Identifier(
                value="john_doe",
                id_type=IdentifierType.USERNAME,
                source="input",
                confidence=0.9,
            )
        ],
        "findings": [],
        "scan_results": [],
        "errors": [],
        "iterations": 0,
        "max_iterations": 3,
        "remaining_budget": 10.0,
        "next_tasks": [("social_osint", "john_doe")],
    }

    mock_add_id = MagicMock()
    engine._add_identifier = mock_add_id

    with patch("src.cli.main._get_module") as mock_get_mod:
        mock_get_mod.return_value = MagicMock()
        await planner.execute_tasks(state)
        assert mock_add_id.called


@pytest.mark.asyncio
async def test_planner_run():
    engine = DeepScanEngine(budget=10.0, max_iterations=2)
    planner = DeepScanPlanner(engine, budget=10.0)

    engine._detect_identifier = MagicMock(
        return_value=Identifier(
            value="test@example.com",
            id_type=IdentifierType.EMAIL,
            source="input",
            confidence=1.0,
        )
    )
    engine._initial_targets = MagicMock(return_value={"test@example.com"})
    engine._get_active_modules = MagicMock(return_value=["social_osint"])
    engine._filter_targets_for_module = MagicMock(return_value={"test@example.com"})
    engine._scan_module = AsyncMock()

    with patch("src.cli.main._get_module") as mock_get_mod:
        mock_get_mod.return_value = MagicMock()
        result = await planner.run("test@example.com")
        assert isinstance(result, DeepScanResult)
        assert result.target == "test@example.com"
        assert result.iterations > 0
