"""Tests for database module."""

from src.core.models import BreachRecord, Finding, ScanResult, Severity


class TestDatabase:
    async def test_init_schema(self, test_db):
        """Schema initializes without error."""
        pass  # fixture handles this

    async def test_save_and_get_scan(self, test_db, sample_scan_result):
        await test_db.save_scan(sample_scan_result)
        retrieved = await test_db.get_scan(sample_scan_result.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == sample_scan_result.scan_id
        assert len(retrieved.findings) == 1

    async def test_get_nonexistent_scan(self, test_db):
        result = await test_db.get_scan("nonexistent")
        assert result is None

    async def test_save_identity(self, test_db, sample_identity):
        await test_db.save_identity(sample_identity)
        retrieved = await test_db.get_identity(sample_identity.zkit_hash)
        assert retrieved is not None
        assert retrieved.zkit_hash == sample_identity.zkit_hash

    async def test_save_scan_with_findings(self, test_db):
        findings = [Finding(id=f"f{i}", module="test", title=f"Finding {i}", severity=Severity.HIGH) for i in range(5)]
        scan = ScanResult(
            scan_id="multi-find",
            module="test",
            target="test",
            findings=findings,
        )
        await test_db.save_scan(scan)
        retrieved = await test_db.get_scan("multi-find")
        assert len(retrieved.findings) == 5

    async def test_breach_records_roundtrip_never_returns_plaintext(self, test_db):
        """Plaintext passwords are never persisted nor returned."""
        scan = ScanResult(
            scan_id="breach-roundtrip",
            module="leak",
            target="a@b.com",
            breach_records=[
                BreachRecord(
                    source="leak",
                    email="a@b.com",
                    username="u",
                    password_hash="hashed",
                    password_plain="SUPERSECRET",
                )
            ],
        )
        await test_db.save_scan(scan)

        retrieved = await test_db.get_scan("breach-roundtrip")
        assert retrieved is not None
        assert len(retrieved.breach_records) == 1
        rec = retrieved.breach_records[0]
        assert rec.email == "a@b.com"
        assert rec.password_hash == "hashed"
        assert rec.password_plain is None

        records = await test_db.get_breach_records("breach-roundtrip")
        assert len(records) == 1
        assert records[0].source == "leak"
        assert records[0].password_plain is None
