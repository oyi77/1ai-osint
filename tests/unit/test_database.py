"""Tests for database module."""

from src.core.models import ScanResult, Finding, Severity


class TestDatabase:
    def test_init_schema(self, test_db):
        """Schema initializes without error."""
        pass  # fixture handles this

    def test_save_and_get_scan(self, test_db, sample_scan_result):
        test_db.save_scan(sample_scan_result)
        retrieved = test_db.get_scan(sample_scan_result.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == sample_scan_result.scan_id
        assert len(retrieved.findings) == 1

    def test_get_nonexistent_scan(self, test_db):
        result = test_db.get_scan("nonexistent")
        assert result is None

    def test_save_identity(self, test_db, sample_identity):
        test_db.save_identity(sample_identity)
        retrieved = test_db.get_identity(sample_identity.zkit_hash)
        assert retrieved is not None
        assert retrieved.zkit_hash == sample_identity.zkit_hash

    def test_save_scan_with_findings(self, test_db):
        findings = [
            Finding(
                id=f"f{i}", module="test", title=f"Finding {i}", severity=Severity.HIGH
            )
            for i in range(5)
        ]
        scan = ScanResult(
            scan_id="multi-find",
            module="test",
            target="test",
            findings=findings,
        )
        test_db.save_scan(scan)
        retrieved = test_db.get_scan("multi-find")
        assert len(retrieved.findings) == 5
