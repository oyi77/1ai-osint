"""Tests for the 1ai-osint Web UI routes.

Run with: python -m pytest tests/unit/test_web_routes.py -v --tb=short
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a FastAPI TestClient with a fresh app instance."""
    from src.web.app import create_app

    app = create_app()
    return TestClient(app)


class TestDashboard:
    """Dashboard route tests."""

    def test_dashboard_returns_200(self, client):
        """GET / should return 200 with HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_dashboard_has_title(self, client):
        """Dashboard page should contain the app title."""
        response = client.get("/")
        assert response.status_code == 200
        assert "1ai-osint" in response.text
        assert "Dashboard" in response.text

    def test_dashboard_empty_state(self, client):
        """Dashboard should show empty state when no scan data exists."""
        response = client.get("/")
        assert response.status_code == 200
        # Should still render stats cards
        assert "Total Scans" in response.text
        assert "Findings" in response.text
        assert "Entities Found" in response.text

    def test_dashboard_stats_structure(self, client):
        """Dashboard should contain stat cards grid."""
        response = client.get("/")
        assert response.status_code == 200
        assert "stats-grid" in response.text

    def test_dashboard_risk_distribution_section(self, client):
        """Dashboard should have Risk Distribution section."""
        response = client.get("/")
        assert response.status_code == 200
        assert "Risk Distribution" in response.text or "risk" in response.text.lower()


class TestEntities:
    """Entity browsing route tests."""

    def test_entities_list_returns_200(self, client):
        """GET /entities should return 200."""
        response = client.get("/entities")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_entities_list_title(self, client):
        """Entities page should have heading."""
        response = client.get("/entities")
        assert response.status_code == 200
        assert "Entities" in response.text

    def test_entities_empty_state(self, client):
        """Entities page should show empty state when no data."""
        response = client.get("/entities")
        assert response.status_code == 200
        assert "entities" in response.text.lower()

    def test_entity_detail_returns_200(self, client):
        """GET /entities/{id} should work for any ID (graceful fallback)."""
        response = client.get("/entities/test-entity-123")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_entity_detail_shows_id(self, client):
        """Entity detail page should display the entity ID."""
        response = client.get("/entities/some-target")
        assert response.status_code == 200
        assert "some-target" in response.text

    def test_entity_detail_empty_timeline(self, client):
        """Entity detail should handle no timeline data gracefully."""
        response = client.get("/entities/unknown-entity")
        assert response.status_code == 200
        assert "Activity Timeline" in response.text or "Timeline" in response.text


class TestReports:
    """Report viewer route tests."""

    def test_reports_list_returns_200(self, client):
        """GET /reports should return 200."""
        response = client.get("/reports")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_reports_list_title(self, client):
        """Reports page should have heading."""
        response = client.get("/reports")
        assert response.status_code == 200
        assert "Reports" in response.text

    def test_reports_empty_state(self, client):
        """Reports page should handle empty state."""
        response = client.get("/reports")
        assert response.status_code == 200
        assert "reports" in response.text.lower()

    def test_report_detail_not_found(self, client):
        """GET /reports/{id} for a nonexistent report should 404."""
        response = client.get("/reports/nonexistent-report-id")
        assert response.status_code == 404

    def test_report_detail_404_message(self, client):
        """404 should contain meaningful error."""
        response = client.get("/reports/does-not-exist")
        assert response.status_code == 404
        assert "not found" in response.text.lower()


class TestTimeline:
    """Timeline route tests."""

    def test_timeline_global_returns_200(self, client):
        """GET /timeline should return 200."""
        response = client.get("/timeline")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_timeline_global_title(self, client):
        """Global timeline page should have proper title."""
        response = client.get("/timeline")
        assert response.status_code == 200
        assert "Timeline" in response.text
        assert "Global" in response.text or "event" in response.text.lower()

    def test_timeline_empty_state(self, client):
        """Timeline should handle empty state."""
        response = client.get("/timeline")
        assert response.status_code == 200
        assert "events" in response.text.lower() or "Event" in response.text

    def test_timeline_per_entity_returns_200(self, client):
        """GET /timeline/{entity_id} should work for any entity."""
        response = client.get("/timeline/test-entity")
        assert response.status_code == 200
        assert "test-entity" in response.text

    def test_timeline_per_entity_empty(self, client):
        """Per-entity timeline should handle empty data gracefully."""
        response = client.get("/timeline/unknown")
        assert response.status_code == 200

    def test_timeline_json_endpoint(self, client):
        """GET /api/timeline/{entity_id}.json should return JSON."""
        response = client.get("/api/timeline/test-entity.json")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"

    def test_timeline_json_structure(self, client):
        """JSON endpoint should have nodes and edges."""
        response = client.get("/api/timeline/test-entity.json")
        data = response.json()
        assert "nodes" in data
        assert "edges" in data

    def test_timeline_json_entity_node(self, client):
        """JSON graph should include the entity as a node."""
        response = client.get("/api/timeline/example.json")
        data = response.json()
        node_ids = [n["id"] for n in data["nodes"]]
        assert "example" in node_ids


class TestStaticFiles:
    """Static file serving tests."""

    def test_static_css_returns_200(self, client):
        """CSS file should be served from /static/."""
        response = client.get("/static/style.css")
        assert response.status_code == 200
        assert "text/css" in response.headers["content-type"]

    def test_static_css_has_dark_theme(self, client):
        """CSS should contain dark theme variables."""
        response = client.get("/static/style.css")
        assert response.status_code == 200
        assert "--bg-primary" in response.text
        assert "#0d1117" in response.text or "dark" in response.text.lower()

    def test_static_css_content(self, client):
        """CSS should have meaningful length."""
        response = client.get("/static/style.css")
        assert response.status_code == 200
        assert len(response.text) > 2000


class TestNavbar:
    """Navigation bar tests."""

    def test_navbar_present(self, client):
        """All pages should include the navbar."""
        response = client.get("/")
        assert response.status_code == 200
        assert "navbar" in response.text
        assert "Dashboard" in response.text
        assert "Entities" in response.text
        assert "Reports" in response.text
        assert "Timeline" in response.text

    def test_navbar_links_work(self, client):
        """All navbar links should return 200."""
        for path in ["/", "/entities", "/reports", "/timeline"]:
            response = client.get(path)
            assert response.status_code == 200, f"{path} returned {response.status_code}"


class TestTemplates:
    """Template rendering tests."""

    def test_base_template_nav(self, client):
        """Base template should render nav bar."""
        response = client.get("/")
        assert "nav-logo" in response.text

    def test_base_template_footer(self, client):
        """Base template should render footer."""
        response = client.get("/")
        assert "footer" in response.text

    def test_entities_template_structure(self, client):
        """Entities page should have data-table."""
        response = client.get("/entities")
        assert response.status_code == 200
        # The table might not be present if there's no data, but card should be
        assert "card" in response.text

    def test_reports_template_structure(self, client):
        """Reports page should have proper structure."""
        response = client.get("/reports")
        assert response.status_code == 200
        assert "card" in response.text

    def test_timeline_template_structure(self, client):
        """Timeline page should have timeline container."""
        response = client.get("/timeline")
        assert response.status_code == 200
        # Should have event log section
        assert "Event" in response.text or "event" in response.text.lower()

    def test_report_detail_template(self, client):
        """Report detail 404 page should have proper structure."""
        response = client.get("/reports/not-here")
        assert response.status_code == 404
        # TemplateResponse will still render through error handler
        assert "detail" in response.text.lower() or "not found" in response.text.lower()

    def test_entity_detail_vis_js_cdn(self, client):
        """Entity detail should include vis.js CDN."""
        response = client.get("/entities/some-entity")
        assert response.status_code == 200
        assert "vis-network" in response.text
