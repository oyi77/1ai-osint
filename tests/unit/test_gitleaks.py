"""Tests for gitleaks module."""

import json
import pytest

from src.modules.gitleaks.scanner import GitleaksModule
from src.modules.gitleaks.parser import parse_gitleaks_json
from src.core.models import Severity


@pytest.fixture
def gitleaks_module():
    return GitleaksModule(zkit_salt="test-salt")


@pytest.fixture
def sample_gitleaks_output():
    return [
        {
            "rule-id": "aws-access-token",
            "description": "AWS Access Token",
            "match": "AKIAIOSFODNN7EXAMPLE",
            "secret": "AKIAIOSFODNN7EXAMPLE",
            "file": "config.js",
            "line": "42",
            "commit": "abc123",
            "author": "Test Author",
            "email": "test@example.com",
            "date": "2023-01-15T10:30:00Z",
        },
        {
            "rule-id": "generic-api-key",
            "description": "Generic API Key",
            "match": "sk-1234567890",
            "secret": "sk-1234567890",
            "file": ".env",
            "line": "5",
            "commit": "def456",
            "author": "Test Author",
            "email": "test@example.com",
            "date": "2023-02-01T12:00:00Z",
        },
    ]


class TestGitleaksParser:
    def test_parse_json_string(self, sample_gitleaks_output):
        raw = json.dumps(sample_gitleaks_output)
        findings = parse_gitleaks_json(raw)
        assert len(findings) == 2
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.HIGH

    def test_parse_json_list(self, sample_gitleaks_output):
        findings = parse_gitleaks_json(sample_gitleaks_output)
        assert len(findings) == 2

    def test_parse_json_dict(self, sample_gitleaks_output):
        findings = parse_gitleaks_json(sample_gitleaks_output[0])
        assert len(findings) == 1

    def test_parse_empty_string(self):
        findings = parse_gitleaks_json("")
        assert findings == []

    def test_parse_invalid_json(self):
        findings = parse_gitleaks_json("not json")
        assert findings == []

    def test_severity_classification(self):
        assert _classify_severity("aws-access-token") == Severity.CRITICAL
        assert _classify_severity("generic-api-key") == Severity.HIGH
        assert _classify_severity("some-other-rule") == Severity.MEDIUM

    def test_finding_has_tags(self, sample_gitleaks_output):
        findings = parse_gitleaks_json(sample_gitleaks_output)
        assert "secret" in findings[0].tags
        assert "gitleaks" in findings[0].tags


class TestGitleaksModule:
    def test_module_name(self, gitleaks_module):
        assert gitleaks_module.name == "gitleaks"

    def test_zkit_hash_consistency(self, gitleaks_module):
        h1 = gitleaks_module.hash_identity("test@example.com")
        h2 = gitleaks_module.hash_identity("test@example.com")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex length

    def test_zkit_hash_different_inputs(self, gitleaks_module):
        h1 = gitleaks_module.hash_identity("alice@example.com")
        h2 = gitleaks_module.hash_identity("bob@example.com")
        assert h1 != h2

    def test_zkit_hash_different_salts(self):
        m1 = GitleaksModule(zkit_salt="salt-a")
        m2 = GitleaksModule(zkit_salt="salt-b")
        h1 = m1.hash_identity("test@example.com")
        h2 = m2.hash_identity("test@example.com")
        assert h1 != h2

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, gitleaks_module):
        result = await gitleaks_module.scan("/nonexistent/path")
        assert result.status == "error"
        assert "does not exist" in result.error

    @pytest.mark.asyncio
    async def test_scan_gitleaks_not_found(self, gitleaks_module, tmp_path):
        gitleaks_module.gitleaks_path = "/nonexistent/gitleaks"
        result = await gitleaks_module.scan(str(tmp_path))
        assert result.status == "error"
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_analyze_findings(self, gitleaks_module, sample_gitleaks_output):
        findings = parse_gitleaks_json(sample_gitleaks_output)
        analysis = await gitleaks_module.analyze(findings)
        assert analysis["total_findings"] == 2
        assert analysis["has_critical"] is True

    def test_to_zkit_node(self, gitleaks_module, sample_gitleaks_output):
        from src.modules.gitleaks.parser import parse_gitleaks_json

        findings = parse_gitleaks_json(sample_gitleaks_output)
        node = gitleaks_module.to_zkit_node(findings[0], attribute_type="secret")
        assert len(node.zkit_hash) == 64
        assert node.attribute_type == "secret"


def _classify_severity(rule_id: str) -> Severity:
    from src.modules.gitleaks.parser import _classify_severity

    return _classify_severity(rule_id)
