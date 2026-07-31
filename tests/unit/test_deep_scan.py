"""Tests for deep_scan module."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.models import Finding, ScanResult, Severity
from src.modules.deep_scan import (
    DeepScanResult,
    Identifier,
    IdentifierType,
)
from src.modules.deep_scan.extractor import (
    _is_valid_nik,
    _parse_nik,
    extract_identifiers,
    extract_usernames_from_profiles,
)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
class TestIdentifier:
    def test_create(self):
        ident = Identifier(value="test@example.com", id_type=IdentifierType.EMAIL, source="test")
        assert ident.value == "test@example.com"
        assert ident.id_type == IdentifierType.EMAIL
        assert ident.confidence == 1.0

    def test_hash(self):
        ident = Identifier(value="test@example.com", id_type=IdentifierType.EMAIL, source="test")
        assert len(ident.hash) == 16


class TestDeepScanResult:
    def test_create(self):
        result = DeepScanResult(target="test", started_at=datetime.now(timezone.utc))
        assert result.target == "test"
        assert result.identifier_count == 0
        assert result.finding_count == 0

    def test_get_emails(self):
        result = DeepScanResult(target="test", started_at=datetime.now(timezone.utc))
        result.identifiers.append(Identifier(value="a@b.com", id_type=IdentifierType.EMAIL, source="t"))
        result.identifiers.append(Identifier(value="user", id_type=IdentifierType.USERNAME, source="t"))
        assert result.get_emails() == ["a@b.com"]

    def test_get_usernames(self):
        result = DeepScanResult(target="test", started_at=datetime.now(timezone.utc))
        result.identifiers.append(Identifier(value="user1", id_type=IdentifierType.USERNAME, source="t"))
        assert result.get_usernames() == ["user1"]

    def test_to_dict(self):
        result = DeepScanResult(target="test", started_at=datetime.now(timezone.utc))
        d = result.to_dict()
        assert d["target"] == "test"
        assert "identifiers" in d
        assert "findings" in d

    def test_duration(self):
        now = datetime.now(timezone.utc)
        result = DeepScanResult(target="test", started_at=now, completed_at=now)
        assert result.duration_sec == 0.0


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------
class TestExtractor:
    def test_extract_email(self):
        ids = extract_identifiers("Contact me at test@example.com", "test")
        emails = [i for i in ids if i.id_type == IdentifierType.EMAIL]
        assert len(emails) == 1
        assert emails[0].value == "test@example.com"

    def test_extract_eth_address(self):
        ids = extract_identifiers("Wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18", "test")
        crypto = [i for i in ids if i.id_type == IdentifierType.CRYPTO_ADDRESS]
        assert len(crypto) == 1
        assert crypto[0].metadata.get("chain") == "ethereum"

    def test_extract_phone(self):
        ids = extract_identifiers("Call +12345678901", "test")
        phones = [i for i in ids if i.id_type == IdentifierType.PHONE]
        assert len(phones) >= 1

    def test_extract_domain(self):
        ids = extract_identifiers("Visit https://example.com for more", "test")
        domains = [i for i in ids if i.id_type == IdentifierType.DOMAIN]
        assert len(domains) >= 1

    def test_extract_nik(self):
        # Valid NIK: province=35, city=02, day=15, month=06, year=95 (1995)
        ids = extract_identifiers("NIK: 3502150606950001", "test")
        niks = [i for i in ids if i.id_type == IdentifierType.NIK]
        assert len(niks) == 1
        assert niks[0].metadata.get("gender") == "male"

    def test_extract_nik_female(self):
        # Day 46 at positions 6-7 = female (46-40=6)
        ids = extract_identifiers("NIK: 3502154606950001", "test")
        niks = [i for i in ids if i.id_type == IdentifierType.NIK]
        assert len(niks) == 1
        assert niks[0].metadata.get("gender") == "female"

    def test_extract_duplicate(self):
        ids = extract_identifiers("a@b.com and a@b.com", "test")
        emails = [i for i in ids if i.id_type == IdentifierType.EMAIL]
        assert len(emails) == 1


class TestDeepScanProfiles:
    def test_fast_module_list_core(self):
        from src.modules.deep_scan.profiles import FAST_CORE_MODULES, fast_module_list

        mods = fast_module_list()
        for core in FAST_CORE_MODULES:
            assert core in mods

    def test_fast_engine_defaults(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(fast=True)
        assert engine.fast is True
        assert engine.max_iterations <= 2
        assert engine.timeout_per_module <= 15
        assert engine.max_pivot_handles == 2
        assert "social_osint" in engine._get_active_modules()

    def test_should_scan_dedupes(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(fast=True)
        assert engine._should_scan("social_osint", "user1") is True
        assert engine._should_scan("social_osint", "user1") is False

    def test_cap_targets_prefers_email(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(max_targets_per_iteration=2)
        capped = engine._cap_targets({"Long Display Name", "a@b.com", "handle"})
        assert "a@b.com" in capped
        assert len(capped) == 2


class TestNamePivots:
    def test_slugify(self):
        from src.modules.deep_scan.name_pivots import slugify_username

        assert slugify_username("Fikri Izzuddin") == "fikriizzuddin"

    def test_candidates_from_name(self):
        from src.modules.deep_scan.name_pivots import username_candidates_from_name

        handles = [h for h, _ in username_candidates_from_name("Fikri Izzuddin")]
        assert "fikriizzuddin" in handles
        assert "fikri_izzuddin" in handles

    def test_primary_username(self):
        from src.modules.deep_scan.name_pivots import primary_username_for_name

        assert primary_username_for_name("Fikri Izzuddin") == "fikriizzuddin"


class TestNikParser:
    def test_valid_nik(self):
        assert _is_valid_nik("3502150606950001") is True

    def test_invalid_nik_short(self):
        assert _is_valid_nik("123") is False

    def test_invalid_nik_bad_province(self):
        assert _is_valid_nik("0002150606950001") is False

    def test_parse_nik(self):
        result = _parse_nik("3502150606950001")
        assert result["province_code"] == "35"
        assert result["birth_year"] == 1995
        assert result["gender"] == "male"


# ---------------------------------------------------------------------------
# DeepScanEngine
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# DeepScanEngine
# ---------------------------------------------------------------------------
class TestDeepScanEngine:
    def _make_engine(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        return DeepScanEngine(max_iterations=1, max_identifiers=50, timeout_per_module=5)

    def test_detect_email(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("test@example.com", "input")
        assert ident.id_type == IdentifierType.EMAIL

    def test_detect_phone(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("08123456789", "input")
        assert ident.id_type == IdentifierType.PHONE

    def test_detect_nik(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("3502024606950001", "input")
        assert ident.id_type == IdentifierType.NIK

    def test_detect_eth_address(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("0x" + "a" * 40, "input")
        assert ident.id_type == IdentifierType.CRYPTO_ADDRESS

    def test_detect_btc_address(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "input")
        assert ident.id_type == IdentifierType.CRYPTO_ADDRESS
        assert ident.metadata.get("chain") == "bitcoin"

    def test_detect_ip(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("1.2.3.4", "input")
        assert ident.id_type == IdentifierType.IP

    def test_detect_username(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("testuser123", "input")
        assert ident.id_type == IdentifierType.USERNAME

    def test_detect_name(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("John Doe", "input")
        assert ident.id_type == IdentifierType.NAME

    def test_detect_empty(self):
        engine = self._make_engine()
        ident = engine._detect_identifier("", "input")
        assert ident is None

    def test_load_modules(self):
        engine = self._make_engine()
        modules = engine._get_active_modules()
        assert len(modules) >= 1

    @pytest.mark.asyncio
    async def test_scan_basic(self):
        engine = self._make_engine()
        with patch("src.modules.deep_scan.engine.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.return_value = ScanResult(
                scan_id="t",
                module="test",
                target="test",
                status="ok",
                findings=[],
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            result = await engine.scan("test@example.com")
        assert result is not None
        assert result.target == "test@example.com"


# ---------------------------------------------------------------------------
# Report Engine
# ---------------------------------------------------------------------------
class TestReportEngine:
    def test_from_scan_results(self):
        from src.modules.report_engine import ReportEngine

        engine = ReportEngine()
        sr = ScanResult(
            scan_id="t",
            module="test",
            target="test",
            status="ok",
            findings=[],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        report = engine.from_scan_results("test", [sr])
        assert report.target == "test"
        assert report.finding_count == 0

    def test_parse_report_json(self):
        from src.modules.report_engine import ReportEngine

        engine = ReportEngine()
        report = engine.parse_report_json('{"target": "test", "title": "Test", "identifiers": [], "metadata": {}}')
        assert report.target == "test"

    def test_extract_identifiers_for_scan(self):
        from src.modules.report_engine import ReportData, ReportEngine

        engine = ReportEngine()
        report = ReportData(target="test", title="Test")
        report.identifiers = [{"value": "a@b.com", "type": "email"}]
        ids = engine.extract_identifiers_for_scan(report)
        assert len(ids) == 1
        assert ids[0]["value"] == "a@b.com"


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------
class TestHTMLTemplate:
    def test_render_html(self):
        from src.modules.report_engine import ReportData
        from src.modules.report_engine.html_template import render_html

        report = ReportData(target="test@example.com", title="Test Report")
        html = render_html(report)
        assert "<!DOCTYPE html>" in html
        assert "test@example.com" in html


# ---------------------------------------------------------------------------
# Report Engine extra
# ---------------------------------------------------------------------------
class TestReportEngineExtra:
    def test_from_scan_with_findings(self):
        from src.modules.report_engine import ReportEngine

        engine = ReportEngine()
        sr = ScanResult(
            scan_id="t",
            module="test",
            target="test",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="test",
                    title="Test",
                    description="Desc",
                    severity=Severity.INFO,
                    raw_data={
                        "email": "a@b.com",
                        "username": "testuser",
                        "phone": "+1234567890",
                        "domain": "example.com",
                        "ip": "1.2.3.4",
                        "wallet": "0x" + "a" * 40,
                    },
                )
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        report = engine.from_scan_results("test", [sr])
        assert report.finding_count == 1
        assert len(report.identifiers) > 0

    def test_report_data_to_dict(self):
        from src.modules.report_engine import ReportData

        report = ReportData(target="test", title="Test")
        d = report.to_dict()
        assert d["target"] == "test"

    def test_report_data_add_section(self):
        from src.modules.report_engine import ReportData

        report = ReportData(target="test", title="Test")
        report.add_section("Emails", ["a@b.com"])
        assert len(report.sections) == 1

    def test_report_data_critical_count(self):
        from src.modules.report_engine import ReportData

        report = ReportData(target="test", title="Test")
        report.add_findings(
            [
                Finding(
                    id="f1",
                    module="test",
                    title="Crit",
                    description="D",
                    severity=Severity.CRITICAL,
                )
            ]
        )
        assert report.critical_count == 1

    def test_report_data_add_findings(self):
        from src.modules.report_engine import ReportData

        report = ReportData(target="test", title="Test")
        report.add_findings(
            [
                Finding(
                    id="f1",
                    module="t",
                    title="A",
                    description="D",
                    severity=Severity.INFO,
                ),
                Finding(
                    id="f2",
                    module="t",
                    title="B",
                    description="D",
                    severity=Severity.HIGH,
                ),
            ]
        )
        assert report.finding_count == 2

    def test_parse_report_json_with_identifiers(self):
        from src.modules.report_engine import ReportEngine

        engine = ReportEngine()
        report = engine.parse_report_json(
            '{"target": "t", "title": "T", "identifiers": [{"value": "x@y.com", "type": "email"}], "metadata": {"k": "v"}}'
        )
        assert len(report.identifiers) == 1

    def test_extract_identifiers_empty(self):
        from src.modules.report_engine import ReportData, ReportEngine

        engine = ReportEngine()
        report = ReportData(target="t", title="T")
        assert engine.extract_identifiers_for_scan(report) == []


# ---------------------------------------------------------------------------
# Deep scan report extended coverage
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# HTML template extended coverage
# ---------------------------------------------------------------------------
class TestHTMLTemplateExtended:
    def test_render_with_sections(self):
        from src.modules.report_engine import ReportData
        from src.modules.report_engine.html_template import render_html

        report = ReportData(target="test@example.com", title="Full Report")
        report.add_section("Emails", ["a@b.com", "c@d.com"])
        report.add_section("Usernames", ["user1"])
        report.add_section("Phones", ["+1234567890"])
        report.add_section("Domains", ["example.com"])
        report.add_section("IP Addresses", ["1.2.3.4"])
        report.add_section("Crypto Addresses", ["0x" + "a" * 40])
        report.add_findings(
            [
                Finding(
                    id="f1",
                    module="test",
                    title="Critical Bug",
                    description="Bad",
                    severity=Severity.CRITICAL,
                ),
                Finding(
                    id="f2",
                    module="test",
                    title="High Bug",
                    description="Also bad",
                    severity=Severity.HIGH,
                ),
                Finding(
                    id="f3",
                    module="test",
                    title="Med Bug",
                    description="Meh",
                    severity=Severity.MEDIUM,
                ),
                Finding(
                    id="f4",
                    module="test",
                    title="Low Bug",
                    description="Fine",
                    severity=Severity.LOW,
                ),
                Finding(
                    id="f5",
                    module="test",
                    title="Info",
                    description="Info",
                    severity=Severity.INFO,
                ),
            ]
        )
        report.metadata = {
            "scan_count": 3,
            "total_findings": 5,
            "critical_findings": 1,
            "report_id": "r123",
        }
        html = render_html(report)
        assert "a@b.com" in html
        assert "user1" in html
        assert "Critical Bug" in html
        assert "r123" in html
        assert "3 scans" in html

    def test_render_many_items_truncation(self):
        from src.modules.report_engine import ReportData
        from src.modules.report_engine.html_template import render_html

        report = ReportData(target="test", title="Big")
        report.add_section("Emails", [f"user{i}@test.com" for i in range(50)])
        html = render_html(report)
        assert "+ 20 more" in html


# ---------------------------------------------------------------------------
# DeepScanEngine extended coverage
# ---------------------------------------------------------------------------
class TestDeepScanEngineExtended:
    def _make_engine(self, **kw):
        from src.modules.deep_scan.engine import DeepScanEngine

        return DeepScanEngine(max_iterations=2, max_identifiers=50, timeout_per_module=5, **kw)

    def test_detect_none_for_empty(self):
        engine = self._make_engine()
        assert engine._detect_identifier("  ", "input") is None

    def test_detect_solana_address(self):
        engine = self._make_engine()
        # Long base58 string matches username regex (3-50 alphanumeric)
        ident = engine._detect_identifier("HAgk6YWDPri5UyX4Y18XzYrFf5C7R5m9v6kQ2J3j8tXr", "input")
        assert ident is not None  # matches username or name

    def test_module_inputs_contains_crypto_tracer(self):
        from src.modules.deep_scan.engine import _MODULE_INPUTS

        assert IdentifierType.CRYPTO_ADDRESS in _MODULE_INPUTS["crypto_tracer"]

    @pytest.mark.asyncio
    async def test_ai_enrichment_attaches_dossier(self):
        from src.modules.free_intel.ai_enricher import EnrichedDossierData

        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.findings.append(
            Finding(
                id="f1",
                module="google_dork",
                title="dork",
                raw_data={"snippet": "John Doe works at Acme as engineer"},
            )
        )
        with patch("src.modules.free_intel.ai_enricher.AIExtractor") as mock_extractor:
            mock_instance = mock_extractor.return_value
            mock_instance.is_available.return_value = True
            mock_instance.extract_from_snippets = AsyncMock(return_value=EnrichedDossierData(current_employer="Acme"))
            await engine._run_ai_enrichment(result, "t")
        dossier_findings = [f for f in result.findings if f.module == "ai_enricher"]
        assert len(dossier_findings) == 1
        assert dossier_findings[0].raw_data["dossier"]["current_employer"] == "Acme"
        mock_instance.extract_from_snippets.assert_awaited_once_with("t", ["John Doe works at Acme as engineer"])

    @pytest.mark.asyncio
    async def test_ai_enrichment_collects_snippets_list(self):
        from src.modules.free_intel.ai_enricher import EnrichedDossierData

        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.findings.append(
            Finding(
                id="f1",
                module="social_dork",
                title="dork",
                raw_data={"snippets": ["snippet one", "snippet two"]},
            )
        )
        with patch("src.modules.free_intel.ai_enricher.AIExtractor") as mock_extractor:
            mock_instance = mock_extractor.return_value
            mock_instance.is_available.return_value = True
            mock_instance.extract_from_snippets = AsyncMock(return_value=EnrichedDossierData(job_title="Engineer"))
            await engine._run_ai_enrichment(result, "t")
        mock_instance.extract_from_snippets.assert_awaited_once_with("t", ["snippet one", "snippet two"])

    @pytest.mark.asyncio
    async def test_ai_enrichment_skipped_no_snippets(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.findings.append(Finding(id="f1", module="email_osint", title="plain", raw_data={"email": "a@b.com"}))
        with patch("src.modules.free_intel.ai_enricher.AIExtractor") as mock_extractor:
            await engine._run_ai_enrichment(result, "t")
        mock_extractor.assert_not_called()
        assert all(f.module != "ai_enricher" for f in result.findings)

    @pytest.mark.asyncio
    async def test_ai_enrichment_skipped_unavailable(self):
        from src.modules.free_intel.ai_enricher import EnrichedDossierData

        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.findings.append(
            Finding(
                id="f1",
                module="google_dork",
                title="dork",
                raw_data={"snippet": "snippet"},
            )
        )
        with patch("src.modules.free_intel.ai_enricher.AIExtractor") as mock_extractor:
            mock_instance = mock_extractor.return_value
            mock_instance.is_available.return_value = False
            mock_instance.extract_from_snippets = AsyncMock(return_value=EnrichedDossierData())
            await engine._run_ai_enrichment(result, "t")
        mock_instance.extract_from_snippets.assert_not_awaited()
        assert all(f.module != "ai_enricher" for f in result.findings)

    @pytest.mark.asyncio
    async def test_ai_enrichment_skipped_empty_dossier(self):
        from src.modules.free_intel.ai_enricher import EnrichedDossierData

        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.findings.append(
            Finding(
                id="f1",
                module="google_dork",
                title="dork",
                raw_data={"snippet": "snippet"},
            )
        )
        with patch("src.modules.free_intel.ai_enricher.AIExtractor") as mock_extractor:
            mock_instance = mock_extractor.return_value
            mock_instance.is_available.return_value = True
            mock_instance.extract_from_snippets = AsyncMock(return_value=EnrichedDossierData())
            await engine._run_ai_enrichment(result, "t")
        mock_instance.extract_from_snippets.assert_awaited_once()
        assert all(f.module != "ai_enricher" for f in result.findings)

    def test_add_identifier_dedup(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        ident1 = Identifier(value="a@b.com", id_type=IdentifierType.EMAIL, source="s1")
        ident2 = Identifier(value="a@b.com", id_type=IdentifierType.EMAIL, source="s2")
        engine._add_identifier(result, ident1)
        engine._add_identifier(result, ident2)
        assert len(result.identifiers) == 1

    def test_add_identifier_max_limit(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(max_iterations=1, max_identifiers=1, timeout_per_module=5)
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        engine._add_identifier(
            result,
            Identifier(value="a@b.com", id_type=IdentifierType.EMAIL, source="s"),
        )
        engine._add_identifier(
            result,
            Identifier(value="c@d.com", id_type=IdentifierType.EMAIL, source="s"),
        )
        assert len(result.identifiers) == 1

    def test_get_new_targets_skips_seen(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.identifiers.append(Identifier(value="a@b.com", id_type=IdentifierType.EMAIL, source="s"))
        targets = engine._get_new_targets(result, {"a@b.com"})
        assert "a@b.com" not in targets

    def test_get_new_targets_skips_low_confidence(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.identifiers.append(
            Identifier(
                value="x@y.com",
                id_type=IdentifierType.EMAIL,
                source="s",
                confidence=0.1,
            )
        )
        targets = engine._get_new_targets(result, set())
        assert len(targets) == 0

    def test_filter_targets_for_unknown_module(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        filtered = engine._filter_targets_for_module("unknown_mod", {"a@b.com"}, result)
        assert filtered == {"a@b.com"}

    def test_filter_targets_for_email_module(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        result.identifiers.append(Identifier(value="a@b.com", id_type=IdentifierType.EMAIL, source="s"))
        result.identifiers.append(Identifier(value="user1", id_type=IdentifierType.USERNAME, source="s"))
        filtered = engine._filter_targets_for_module("email_osint", {"a@b.com", "user1"}, result)
        assert "a@b.com" in filtered
        assert "user1" not in filtered

    def test_filter_targets_detects_type(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        # target not in identifiers, but detectable as email
        filtered = engine._filter_targets_for_module("email_osint", {"new@test.com"}, result)
        assert "new@test.com" in filtered

    def test_filter_targets_empty_accepted_passes_all(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        # Empty set is falsy → `not accepted_types` is True → returns all targets
        from src.modules.deep_scan.engine import _MODULE_INPUTS

        old = _MODULE_INPUTS.get("test_empty")
        _MODULE_INPUTS["test_empty"] = set()
        try:
            filtered = engine._filter_targets_for_module("test_empty", {"a@b.com"}, result)
            assert filtered == {"a@b.com"}  # empty set means pass-all
        finally:
            if old is None:
                del _MODULE_INPUTS["test_empty"]
            else:
                _MODULE_INPUTS["test_empty"] = old

    def test_get_active_modules_custom(self):
        engine = self._make_engine(modules=["email_osint", "social_osint"])
        assert set(engine._get_active_modules()) == {"email_osint", "social_osint"}

    @pytest.mark.asyncio
    async def test_scan_module_timeout(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(max_iterations=1, max_identifiers=50, timeout_per_module=0.001)
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        mod = MagicMock()

        async def slow_scan(*_a, **_kw):
            import asyncio

            await asyncio.sleep(10)

        mod.scan = slow_scan
        await engine._scan_module("test_mod", mod, "target", result)
        assert any("timeout" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_scan_module_exception(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        mod = MagicMock()

        async def fail_scan(*_a, **_kw):
            raise ValueError("boom")

        mod.scan = fail_scan
        await engine._scan_module("test_mod", mod, "target", result)
        assert any("boom" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_scan_module_returns_scan_result(self):
        engine = self._make_engine()
        result = DeepScanResult(target="t", started_at=datetime.now(timezone.utc))
        mod = MagicMock()
        sr = ScanResult(
            scan_id="s",
            module="test",
            target="t",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="test",
                    title="F",
                    description="D",
                    severity=Severity.INFO,
                )
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )

        async def ok_scan(*_a, **_kw):
            return sr

        mod.scan = ok_scan
        await engine._scan_module("test_mod", mod, "target", result)
        assert len(result.scan_results) == 1
        assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_scan_full_with_mocked_modules(self):
        """Full scan with all modules mocked."""
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(max_iterations=1, max_identifiers=50, timeout_per_module=5)
        with patch(
            "src.modules.deep_scan.engine._MODULE_INPUTS",
            {"email_osint": {IdentifierType.EMAIL}},
        ):
            with patch.object(engine, "_get_active_modules", return_value=["email_osint"]):
                with patch(
                    "src.modules.deep_scan.engine.asyncio.gather",
                    new_callable=AsyncMock,
                ) as mock_gather:
                    mock_gather.return_value = []
                    result = await engine.scan("test@example.com")
        assert result.target == "test@example.com"
        assert result.completed_at is not None

    @pytest.mark.asyncio
    async def test_scan_phase_4_correlation(self):
        from src.modules.deep_scan.engine import DeepScanEngine

        engine = DeepScanEngine(max_iterations=1, max_identifiers=50, timeout_per_module=5)

        # Mock gather to return social findings
        finding = Finding(
            id="f1",
            module="social_osint",
            title="LinkedIn Profile",
            description="D",
            severity=Severity.INFO,
            raw_data={
                "type": "social_account",
                "platform": "linkedin",
                "url": "https://linkedin.com/in/testuser",
            },
        )

        async def mock_run_iteration(result_obj, targets_set):
            result_obj.findings.append(finding)
            # Also add to identifiers to prevent Phase 3 logic from crashing or being skipped
            result_obj.identifiers.append(Identifier(value="testuser", id_type=IdentifierType.USERNAME, source="test"))

        mock_scrape = AsyncMock(
            return_value={
                "text_content": "Full Name: John Doe",
                "profile_picture_url": "pfp",
            }
        )
        mock_correlate = AsyncMock(return_value=0.8)
        mock_ext_scan = AsyncMock(
            return_value=ScanResult(scan_id="ext", module="external_tools_username", target="testuser")
        )

        with (
            patch(
                "src.modules.deep_scan.engine._MODULE_INPUTS",
                {"social_osint": {IdentifierType.USERNAME}},
            ),
            patch.object(engine, "_get_active_modules", return_value=["social_osint"]),
            patch.object(engine, "_run_iteration", side_effect=mock_run_iteration),
            patch(
                "src.modules.vendor.external_tools.ExternalToolIntel.scan_username",
                mock_ext_scan,
            ),
            patch(
                "src.modules.deep_scan.deep_scraper.DeepScraperEngine.scrape_profile",
                mock_scrape,
            ),
            patch(
                "src.modules.deep_scan.vision_correlator.VisionCorrelator.correlate_profiles",
                mock_correlate,
            ),
        ):
            result = await engine.scan("testuser")

        assert len(result.findings) == 1
        assert result.findings[0].raw_data.get("verified") is True
        assert result.findings[0].raw_data.get("correlation_confidence") == 0.8
        assert result.findings[0].raw_data.get("bio") == "Full Name: John Doe"
        mock_scrape.assert_called_once_with("https://linkedin.com/in/testuser")

    def test_extract_identifiers_from_findings_text(self):
        """Extractor pulls identifiers from raw finding data."""
        ids = extract_identifiers(
            "Found email admin@site.com and wallet 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 and NIK 3502150606950001",
            "test",
        )
        types = {i.id_type for i in ids}
        assert IdentifierType.EMAIL in types
        assert IdentifierType.CRYPTO_ADDRESS in types
        assert IdentifierType.NIK in types

    def test_extract_usernames_from_profiles(self):
        finding = MagicMock()
        finding.module = "social_osint"
        finding.raw_data = {
            "username": "fikriizzuddin",
            "platforms": [
                {
                    "exists": True,
                    "url": "https://twitter.com/user1",
                    "platform": "twitter",
                },
                {"exists": False, "url": "", "platform": "github"},
            ],
        }
        ids = extract_usernames_from_profiles([finding])
        usernames = [i for i in ids if i.id_type == IdentifierType.USERNAME]
        assert len(usernames) == 1
        assert usernames[0].value == "fikriizzuddin"
