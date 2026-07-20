"""Tests for gitleaks module."""

import pytest

from src.modules.gitleaks.scanner import GitleaksModule
from src.core.models import Severity


@pytest.fixture
def gitleaks_module():
    return GitleaksModule(zkit_salt="test-salt")


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
    async def test_analyze_findings(self, gitleaks_module):
        from src.core.models import Finding

        findings = [
            Finding(id="f1", module="gitleaks", title="AWS Key", severity=Severity.CRITICAL),
            Finding(id="f2", module="gitleaks", title="Generic Key", severity=Severity.HIGH),
        ]
        analysis = await gitleaks_module.analyze(findings)
        assert analysis["total_findings"] == 2
        assert analysis["has_critical"]

    def test_to_zkit_node(self, gitleaks_module):
        from src.core.models import Finding

        finding = Finding(id="f1", module="gitleaks", title="AWS Key", severity=Severity.CRITICAL)
        node = gitleaks_module.to_zkit_node(finding, attribute_type="secret")
        assert len(node.zkit_hash) == 64
        assert node.attribute_type == "secret"
