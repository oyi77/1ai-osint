"""Tests for web route internal helper functions.

Focuses on exercising uncovered code paths in _load_scan_history,
_compute_dashboard_stats, _load_all_entities, and _load_entity_timeline.
"""

from __future__ import annotations

import json

# =============================================================================
# Dashboard internal function tests
# =============================================================================


class TestLoadScanHistory:
    """Test _load_scan_history edge cases."""

    def test_skips_rate_limit_files(self, monkeypatch, tmp_path):
        """Files matching skip patterns should be ignored."""
        from src.web.routes.dashboard import _load_scan_history

        monkeypatch.chdir(tmp_path)

        # Create a scan file that should be picked up
        scan_file = tmp_path / "scan_result.json"
        scan_file.write_text(json.dumps({"scan_id": "test-001", "findings": []}))

        # Create a file that should be skipped
        skip_file = tmp_path / ".osint_rate_limit.json"
        skip_file.write_text(json.dumps({"limit": 10}))

        result = _load_scan_history()
        assert len(result) == 1
        assert result[0]["scan_id"] == "test-001"

    def test_skips_package_lock(self, monkeypatch, tmp_path):
        """package-lock.json should be skipped."""
        from src.web.routes.dashboard import _load_scan_history

        monkeypatch.chdir(tmp_path)

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({"name": "pkg"}))
        result = _load_scan_history()
        assert len(result) == 0

    def test_skips_cov_json(self, monkeypatch, tmp_path):
        """cov.json should be skipped."""
        from src.web.routes.dashboard import _load_scan_history

        monkeypatch.chdir(tmp_path)

        cov = tmp_path / "cov.json"
        cov.write_text(json.dumps({"coverage": 80}))
        result = _load_scan_history()
        assert len(result) == 0

    def test_list_data_with_findings(self, monkeypatch, tmp_path):
        """JSON list of scan results should be parsed correctly."""
        from src.web.routes.dashboard import _load_scan_history

        monkeypatch.chdir(tmp_path)

        multi = tmp_path / "multi_results.json"
        multi.write_text(
            json.dumps(
                [
                    {"scan_id": "s1", "findings": []},
                    {"scan_id": "s2", "findings": [{"title": "X"}]},
                ]
            )
        )
        result = _load_scan_history()
        assert len(result) == 2
        ids = {r["scan_id"] for r in result}
        assert ids == {"s1", "s2"}

    def test_list_item_missing_keys(self, monkeypatch, tmp_path):
        """List items with report_id not scanned_id are collected via dict-level check."""
        from src.web.routes.dashboard import _load_scan_history

        monkeypatch.chdir(tmp_path)

        data_file = tmp_path / "report.json"
        # When the file is a list, each item needs scan_id or findings
        data_file.write_text(
            json.dumps(
                [
                    {"scan_id": "s1", "modules_run": ["a"]},
                    {"findings": []},  # matches via findings
                ]
            )
        )
        result = _load_scan_history()
        assert len(result) == 2

    def test_invalid_json_skipped(self, monkeypatch, tmp_path):
        """Files with invalid JSON should be skipped silently."""
        from src.web.routes.dashboard import _load_scan_history

        monkeypatch.chdir(tmp_path)

        bad = tmp_path / "bad.json"
        bad.write_text("{invalid json}")
        result = _load_scan_history()
        assert len(result) == 0


class TestComputeDashboardStats:
    """Test _compute_dashboard_stats with various data shapes."""

    def test_empty_history(self):
        from src.web.routes.dashboard import _compute_dashboard_stats

        stats = _compute_dashboard_stats([])
        assert stats["total_scans"] == 0
        assert stats["total_findings"] == 0
        assert stats["total_entities"] == 0
        assert stats["modules_run"] == []
        assert stats["risk_distribution"] == {}

    def test_with_findings_and_severity(self):
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s1",
                "findings": [
                    {"title": "Found X", "severity": "high", "target": "victim.com"},
                    {"title": "Found Y", "severity": "medium", "target": "victim.com"},
                ],
                "module": "leak_scanner",
                "modules_run": ["leak_scanner"],
            }
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1
        assert stats["total_findings"] == 2
        assert stats["total_entities"] == 1
        # module + modules_run both count → 2
        assert ("leak_scanner", 2) in stats["modules_run"]
        assert stats["risk_distribution"]["high"] == 1
        assert stats["risk_distribution"]["medium"] == 1

    def test_with_evidence_and_identities(self):
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s2",
                "findings": [],
                "evidence": [
                    {"entity_id": "user1"},
                    {"id": "user2"},
                    {"title": "some evidence", "entity_id": None},
                ],
                "identities": [
                    {"id": "user1", "zkit_hash": "abc123"},
                    {"zkit_hash": "def456"},
                ],
                "modules_run": ["social"],
            }
        ]
        stats = _compute_dashboard_stats(history)
        # user1 appears in both evidence and identities -> counted once
        # user2 appears in evidence
        assert stats["total_entities"] >= 2
        assert stats["total_scans"] == 1

    def test_with_risk_block(self):
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s3",
                "findings": [],
                "risk": {"level": "critical"},
            },
            {
                "scan_id": "s4",
                "findings": [],
                "risk": {"level": "low"},
            },
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["risk_distribution"]["critical"] == 1
        assert stats["risk_distribution"]["low"] == 1

    def test_findings_non_list(self):
        """findings being a non-list should not crash."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [{"scan_id": "s5", "findings": "not_a_list", "modules_run": []}]
        stats = _compute_dashboard_stats(history)
        assert stats["total_findings"] == 0
        assert stats["total_scans"] == 1

    def test_modules_run_non_list(self):
        """modules_run being a non-list should not crash."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [{"scan_id": "s6", "findings": [], "modules_run": "not_a_list"}]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1

    def test_evidence_non_list(self):
        """evidence being non-list should work."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [{"scan_id": "s7", "findings": [], "evidence": "not_a_list"}]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1

    def test_identities_non_list(self):
        """identities being non-list should work."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s8",
                "findings": [],
                "identities": "not_a_list",
                "modules_run": [],
            }
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1

    def test_risk_not_dict(self):
        """risk being a non-dict should not crash."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s9",
                "findings": [],
                "risk": "not_a_dict",
                "modules_run": [],
            }
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1

    def test_evidence_item_not_dict(self):
        """Non-dict items in evidence should be skipped."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s10",
                "findings": [],
                "evidence": ["string_item", {"entity_id": "user3"}],
                "modules_run": [],
            }
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1

    def test_identity_item_not_dict(self):
        """Non-dict items in identities should be skipped."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s11",
                "findings": [],
                "identities": [123, {"id": "user4"}],
                "modules_run": [],
            }
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["total_scans"] == 1

    def test_finding_item_not_dict(self):
        """Non-dict items in findings should be skipped."""
        from src.web.routes.dashboard import _compute_dashboard_stats

        history = [
            {
                "scan_id": "s12",
                "findings": ["not_a_dict", {"title": "good", "severity": "info", "target": "tgt"}],
                "modules_run": ["mod"],
            }
        ]
        stats = _compute_dashboard_stats(history)
        assert stats["total_findings"] == 1


# =============================================================================
# Entities internal function tests
# =============================================================================


class TestLoadAllEntities:
    """Test _load_all_entities edge cases."""

    def test_empty_directory(self, monkeypatch, tmp_path):
        """No JSON files yields empty list."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        result = _load_all_entities()
        assert result == []

    def test_loads_target_entities(self, monkeypatch, tmp_path):
        """Entities extracted from scan targets."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "s1",
                    "target": "user@example.com",
                    "module": "email_scanner",
                    "findings": [],
                    "started_at": "2024-01-01T00:00:00",
                    "completed_at": "2024-01-01T01:00:00",
                }
            )
        )
        result = _load_all_entities()
        assert len(result) == 1
        assert result[0]["id"] == "user@example.com"
        assert result[0]["source"] == "email_scanner"

    def test_entities_from_findings_raw_data(self, monkeypatch, tmp_path):
        """Entities extracted from finding raw_data fields."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "s2",
                    "target": "corp.com",
                    "findings": [
                        {
                            "module": "breach_scanner",
                            "severity": "high",
                            "title": "breach",
                            "raw_data": {
                                "email": "leaked@corp.com",
                                "domain": "corp.com",
                            },
                        }
                    ],
                    "started_at": "2024-01-01T00:00:00",
                    "completed_at": "2024-01-01T01:00:00",
                }
            )
        )
        result = _load_all_entities()
        ids = {e["id"] for e in result}
        # target and raw_data email + domain
        assert "leaked@corp.com" in ids
        assert "corp.com" in ids

    def test_entities_from_findings_direct_fields(self, monkeypatch, tmp_path):
        """Entities extracted from finding key field lookups."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "s3",
                    "target": "main",
                    "findings": [
                        {
                            "module": "finder",
                            "severity": "medium",
                            "title": "found",
                            "username": "jdoe",
                            "raw_data": None,
                        }
                    ],
                    "started_at": "2024-01-01T00:00:00",
                    "completed_at": "2024-01-01T01:00:00",
                }
            )
        )
        result = _load_all_entities()
        ids = {e["id"] for e in result}
        assert "jdoe" in ids

    def test_entity_with_risk_from_deep_scan(self, monkeypatch, tmp_path):
        """Risk block from deep scan reports."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "deep_scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "deep1",
                    "target": "suspicious.org",
                    "findings": [],
                    "risk": {"level": "critical"},
                    "started_at": "2024-01-01T00:00:00",
                    "completed_at": "2024-01-01T01:00:00",
                }
            )
        )
        result = _load_all_entities()
        assert len(result) == 1
        assert result[0]["risk_level"] == "critical"

    def test_invalid_json_skips(self, monkeypatch, tmp_path):
        """Invalid JSON files are skipped."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        bad = tmp_path / "bad.json"
        bad.write_text("{bad}")
        result = _load_all_entities()
        assert result == []

    def test_list_format_data(self, monkeypatch, tmp_path):
        """List of scan results should all be processed."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        multi = tmp_path / "multi.json"
        multi.write_text(
            json.dumps(
                [
                    {"scan_id": "a", "target": "alice", "findings": []},
                    {"scan_id": "b", "target": "bob", "findings": []},
                ]
            )
        )
        result = _load_all_entities()
        assert len(result) == 2

    def test_non_dict_list_item_skips(self, monkeypatch, tmp_path):
        """Non-dict items in a JSON list are skipped."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)
        data = tmp_path / "mixed.json"
        data.write_text(
            json.dumps(
                [
                    {"scan_id": "a", "target": "alice", "findings": []},
                    "not_a_dict",
                    42,
                ]
            )
        )
        result = _load_all_entities()
        assert len(result) == 1
        assert result[0]["id"] == "alice"

    def test_skip_patterns(self, monkeypatch, tmp_path):
        """Files matching skip patterns are ignored."""
        from src.web.routes.entities import _load_all_entities

        monkeypatch.chdir(tmp_path)

        allowed = tmp_path / "scan.json"
        allowed.write_text(json.dumps({"scan_id": "s1", "target": "tgt", "findings": []}))

        skipped = tmp_path / "package-lock.json"
        skipped.write_text(json.dumps({"name": "pkg"}))

        result = _load_all_entities()
        assert len(result) == 1
        assert result[0]["id"] == "tgt"


class TestLoadEntityTimeline:
    """Test _load_entity_timeline edge cases."""

    def test_empty_for_unknown_entity(self, monkeypatch, tmp_path):
        """Unknown entity returns empty timeline."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        events = _load_entity_timeline("nonexistent")
        assert events == []

    def test_timeline_from_scan_target(self, monkeypatch, tmp_path):
        """Events created from scan target matching."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "s1",
                    "target": "victim.com",
                    "module": "dns_scanner",
                    "findings": [],
                    "started_at": "2024-01-01T00:00:00",
                }
            )
        )
        events = _load_entity_timeline("victim.com")
        assert len(events) >= 1
        assert events[0]["event_type"] == "scan"
        assert events[0]["source"] == "dns_scanner"

    def test_timeline_from_findings(self, monkeypatch, tmp_path):
        """Events created from matching findings."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "s2",
                    "target": "other.com",
                    "module": "scanner",
                    "findings": [
                        {
                            "id": "f1",
                            "title": "found leak for victim.com",
                            "severity": "high",
                            "confidence": 0.9,
                            "module": "leak_check",
                            "timestamp": "2024-01-02T00:00:00",
                            "raw_data": {"domain": "victim.com"},
                        }
                    ],
                    "started_at": "2024-01-01T00:00:00",
                }
            )
        )
        events = _load_entity_timeline("victim.com")
        assert len(events) >= 1
        assert events[0]["event_type"] == "finding"
        assert events[0]["context"]["finding_id"] == "f1"

    def test_case_insensitive_matching(self, monkeypatch, tmp_path):
        """Entity matching should be case-insensitive."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "scan.json"
        scan.write_text(
            json.dumps(
                {
                    "scan_id": "s3",
                    "target": "Victim.com",
                    "module": "scanner",
                    "findings": [],
                    "started_at": "2024-01-01T00:00:00",
                }
            )
        )
        events = _load_entity_timeline("victim.com")
        assert len(events) >= 1

    def test_timeline_uses_report_id_fallback(self, monkeypatch, tmp_path):
        """When scan_id is missing, report_id should be used."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        scan = tmp_path / "report.json"
        scan.write_text(
            json.dumps(
                {
                    "report_id": "rpt-001",
                    "target": "test.org",
                    "module": "reporter",
                    "findings": [],
                    "started_at": "2024-01-01T00:00:00",
                }
            )
        )
        events = _load_entity_timeline("test.org")
        assert len(events) >= 1
        assert events[0]["context"]["scan_id"] == "rpt-001"

    def test_invalid_json_skipped(self, monkeypatch, tmp_path):
        """Invalid JSON files are skipped in timeline loading."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        bad = tmp_path / "bad.json"
        bad.write_text("{bad}")
        result = _load_entity_timeline("anything")
        assert result == []

    def test_non_dict_in_list(self, monkeypatch, tmp_path):
        """Non-dict items in JSON lists should be skipped."""
        from src.web.routes.entities import _load_entity_timeline

        monkeypatch.chdir(tmp_path)
        data = tmp_path / "mixed.json"
        data.write_text(
            json.dumps(
                [
                    {"scan_id": "a", "target": "test.me", "findings": [], "started_at": "2024-01-01T00:00:00"},
                    "bad_item",
                ]
            )
        )
        events = _load_entity_timeline("test.me")
        assert len(events) >= 1
