"""Tests for the compliance layer (blueprint Layer 3 — S1 registry + S2 audit log)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.core.compliance import (
    DEFAULT_RETENTION_DAYS,
    LegalBasis,
    SourceCompliance,
    audit_log_path,
    get_compliance,
    is_consent_required,
    purge_expired_audit_entries,
    read_audit_entries,
    record_audit,
    registered_sources,
)

# ── S1: Legal-basis registry ──────────────────────────────────────────────────


class TestLegalBasisRegistry:
    def test_enum_values(self):
        values = {lb.value for lb in LegalBasis}
        assert values == {
            "government_open_data",
            "legitimate_interest",
            "consent",
            "public_api_tos",
            "undocumented",
        }

    def test_known_source_hibp_is_public_api_tos(self):
        comp = get_compliance("hibp")
        assert comp.legal_basis == LegalBasis.PUBLIC_API_TOS
        assert comp.retention_days == DEFAULT_RETENTION_DAYS
        assert comp.requires_consent is False

    def test_known_source_sherlock_is_legitimate_interest(self):
        comp = get_compliance("sherlock")
        assert comp.legal_basis == LegalBasis.LEGITIMATE_INTEREST

    def test_government_open_data_for_pddikti(self):
        comp = get_compliance("pddikti_intel")
        assert comp.legal_basis == LegalBasis.GOVERNMENT_OPEN_DATA

    def test_paid_breach_db_is_undocumented_with_review_note(self):
        comp = get_compliance("dehashed")
        assert comp.legal_basis == LegalBasis.UNDOCUMENTED
        assert "review" in comp.tos_notes.lower()

    def test_unknown_source_defaults_to_undocumented(self):
        comp = get_compliance("totally_unknown_source")
        assert comp.legal_basis == LegalBasis.UNDOCUMENTED
        assert comp.retention_days == DEFAULT_RETENTION_DAYS

    def test_registered_sources_contains_backfill(self):
        registered = registered_sources()
        assert "hibp" in registered
        assert "sherlock" in registered
        assert "dehashed" in registered

    def test_is_consent_required_false_by_default(self):
        assert is_consent_required("hibp") is False
        assert is_consent_required("unknown_source") is False

    def test_consent_flagged_source(self):
        comp = SourceCompliance(
            source="sensitive_test",
            legal_basis=LegalBasis.CONSENT,
            requires_consent=True,
        )
        assert comp.requires_consent is True


# ── S2: Audit log ─────────────────────────────────────────────────────────────


class TestAuditLog:
    @pytest.fixture(autouse=True)
    def _isolate_audit_path(self, tmp_path, monkeypatch):
        """Point audit log at a temp file for every test."""
        monkeypatch.setattr("src.core.compliance.settings.audit_log_path", str(tmp_path / "audit.jsonl"))
        yield

    def test_record_audit_writes_jsonl(self):
        entry = record_audit(
            source="hibp",
            target="test@example.com",
            requester="unit-test",
            outcome="ok",
            findings_count=3,
        )
        assert entry.legal_basis == LegalBasis.PUBLIC_API_TOS.value
        assert entry.retention_days == DEFAULT_RETENTION_DAYS

        path = audit_log_path()
        assert path.exists()
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["source"] == "hibp"
        assert data["target"] == "test@example.com"
        assert data["requester"] == "unit-test"
        assert data["outcome"] == "ok"
        assert data["findings_count"] == 3
        assert data["legal_basis"] == "public_api_tos"
        assert data["retention_days"] == DEFAULT_RETENTION_DAYS

    def test_record_audit_explicit_legal_basis_override(self):
        entry = record_audit(
            source="dehashed",
            target="x@y.com",
            requester="tester",
            outcome="error",
            legal_basis="undocumented",
        )
        assert entry.legal_basis == "undocumented"

    def test_read_audit_entries_returns_newest_first(self):
        record_audit(source="a", target="t1", requester="r", outcome="ok", findings_count=1)
        record_audit(source="b", target="t2", requester="r", outcome="empty")
        entries = read_audit_entries()
        assert len(entries) == 2
        assert entries[0]["source"] == "b"  # newest first

    def test_read_audit_entries_empty_when_no_file(self, tmp_path):
        assert read_audit_entries() == []

    def test_purge_expired_entries(self):
        # Write one old entry (40 days ago, retention 30) and one fresh.
        old = datetime.now(timezone.utc) - timedelta(days=40)
        fresh = datetime.now(timezone.utc)
        path = audit_log_path()
        path.write_text(
            json.dumps(
                {
                    "id": "old",
                    "timestamp": old.isoformat(),
                    "source": "a",
                    "target": "t",
                    "legal_basis": "public_api_tos",
                    "requester": "r",
                    "outcome": "ok",
                    "findings_count": 0,
                    "retention_days": DEFAULT_RETENTION_DAYS,
                }
            )
            + "\n"
            + json.dumps(
                {
                    "id": "fresh",
                    "timestamp": fresh.isoformat(),
                    "source": "b",
                    "target": "t",
                    "legal_basis": "public_api_tos",
                    "requester": "r",
                    "outcome": "ok",
                    "findings_count": 0,
                    "retention_days": DEFAULT_RETENTION_DAYS,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        purged = purge_expired_audit_entries()
        assert purged == 1
        remaining = read_audit_entries()
        assert len(remaining) == 1
        assert remaining[0]["id"] == "fresh"

    def test_purge_skips_malformed_lines(self):
        path = audit_log_path()
        path.write_text("not-json\n", encoding="utf-8")
        assert purge_expired_audit_entries() == 0
        assert path.exists()

    def test_purge_no_file_returns_zero(self, tmp_path):
        assert purge_expired_audit_entries() == 0


# ── Adapter wiring: run_source_scan audit + consent gate ──────────────────────


class TestSourceAdapterCompliance:
    @pytest.fixture(autouse=True)
    def _isolate_audit_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.core.compliance.settings.audit_log_path", str(tmp_path / "audit.jsonl"))
        yield

    @pytest.mark.asyncio
    async def test_successful_scan_records_ok_audit(self):
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = [
            type(
                "RL",
                (),
                {
                    "text": '{"email": "a@b.com", "domain": "b.com"}',
                    "source_url": "https://example.com",
                },
            )()
        ]
        result = await run_source_scan("hibp", "a@b.com", source, requester="test-requester")
        assert result is not None
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "ok"
        assert entries[0]["findings_count"] >= 1
        assert entries[0]["requester"] == "test-requester"
        assert entries[0]["legal_basis"] == "public_api_tos"

    @pytest.mark.asyncio
    async def test_empty_scan_records_empty_audit(self):
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = []
        result = await run_source_scan("hibp", "a@b.com", source)
        assert result is None
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "empty"

    @pytest.mark.asyncio
    async def test_error_scan_records_error_audit(self):
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.side_effect = RuntimeError("boom")
        result = await run_source_scan("hibp", "a@b.com", source)
        assert result is None
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "error"

    @pytest.mark.asyncio
    async def test_consent_required_source_is_blocked_without_query(self):
        from src.modules.deep_scan.source_adapter import run_source_scan

        # Register a consent-flagged source on the fly.
        with patch(
            "src.modules.deep_scan.source_adapter.is_consent_required",
            return_value=True,
        ):
            with patch(
                "src.modules.deep_scan.source_adapter.get_compliance",
                return_value=SourceCompliance(
                    source="sensitive",
                    legal_basis=LegalBasis.CONSENT,
                    requires_consent=True,
                ),
            ):
                source = AsyncMock()
                result = await run_source_scan("sensitive", "a@b.com", source, requester="tester")
        assert result is None
        # The underlying source must never be queried.
        source.search_for_address.assert_not_awaited()
        entries = read_audit_entries()
        assert len(entries) == 1
        assert entries[0]["outcome"] == "blocked"
        assert entries[0]["legal_basis"] == "consent"

    @pytest.mark.asyncio
    async def test_unknown_source_is_audited_as_undocumented(self):
        from src.modules.deep_scan.source_adapter import run_source_scan

        source = AsyncMock()
        source.search_for_address.return_value = []
        await run_source_scan("brand_new_source", "t@t.com", source)
        entries = read_audit_entries()
        assert entries[0]["legal_basis"] == "undocumented"
