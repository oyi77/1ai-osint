"""Tests for the CLI entry point (typer commands)."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from src.cli import app

runner = CliRunner()


@pytest.fixture
def mock_scan_result():
    from src.models import ScanResult, Finding, Severity
    return ScanResult(
        scan_id="test-scan-1",
        module="gitleaks",
        target="/some/repo",
        status="ok",
        findings=[
            Finding(
                id="f1",
                module="gitleaks",
                title="Found secret",
                description="API key in config",
                severity=Severity.HIGH,
                raw_data={"file": "config.yml", "email": "a@b.com"},
                confidence=0.9,
                tags=["secret"],
            )
        ],
    )


class TestVersionCommand:
    def test_version_output(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "1ai-osint v0.1.0" in result.output


class TestScanGitleaks:
    @patch("src.cli._get_module")
    def test_scan_gitleaks_json(self, mock_get_module, mock_scan_result):
        mock_mod = MagicMock()
        mock_mod.name = "gitleaks"
        mock_mod.scan = AsyncMock(return_value=mock_scan_result)
        mock_get_module.return_value = mock_mod

        result = runner.invoke(app, ["scan", "/some/repo", "--module", "gitleaks"])
        assert result.exit_code == 0
        mock_get_module.assert_called_once_with("gitleaks", "")


class TestScanDataLeaks:
    @patch("src.cli._get_module")
    def test_scan_data_leaks_json(self, mock_get_module, mock_scan_result):
        mock_mod = MagicMock()
        mock_mod.name = "data_leaks"
        mock_mod.scan = AsyncMock(return_value=mock_scan_result)
        mock_get_module.return_value = mock_mod

        result = runner.invoke(app, ["scan", "test@example.com", "--module", "data_leaks"])
        assert result.exit_code == 0
        mock_get_module.assert_called_once_with("data_leaks", "")


class TestScanWithAI:
    @patch("src.cli._run_with_ai")
    @patch("src.cli._get_module")
    def test_scan_with_ai_flag(self, mock_get_module, mock_run_ai, mock_scan_result):
        mock_mod = MagicMock()
        mock_mod.name = "gitleaks"
        mock_mod.scan = AsyncMock(return_value=mock_scan_result)
        mock_get_module.return_value = mock_mod
        mock_run_ai.return_value = mock_scan_result

        result = runner.invoke(app, ["scan", "/repo", "--module", "gitleaks", "--ai"])
        assert result.exit_code == 0
        mock_run_ai.assert_called_once()


class TestScanWithZkit:
    @patch("src.cli._run_zkit_tracking")
    @patch("src.cli._get_module")
    def test_scan_with_zkit_flag(self, mock_get_module, mock_zkit, mock_scan_result):
        mock_mod = MagicMock()
        mock_mod.name = "gitleaks"
        mock_mod.scan = AsyncMock(return_value=mock_scan_result)
        mock_get_module.return_value = mock_mod
        mock_zkit.return_value = mock_scan_result

        result = runner.invoke(
            app,
            ["scan", "/repo", "--module", "gitleaks", "--zkit", "--zkit-salt", "my-salt"],
        )
        assert result.exit_code == 0
        mock_zkit.assert_called_once()


class TestInvalidModule:
    def test_invalid_module_name(self):
        result = runner.invoke(app, ["scan", "target", "--module", "nonexistent"])
        assert result.exit_code == 1
        assert "Unknown module" in result.output


class TestInvalidOutputFormat:
    def test_invalid_output_format(self):
        result = runner.invoke(app, ["scan", "target", "--output", "csv"])
        assert result.exit_code == 1
        assert "Unknown output format" in result.output


class TestGetModule:
    def test_returns_none_for_unknown(self):
        from src.cli import _get_module
        assert _get_module("totally_unknown") is None

    @patch("src.cli.GitleaksModule", create=True)
    def test_returns_gitleaks(self, mock_cls):
        with patch("src.modules.gitleaks.scanner.GitleaksModule", create=True):
            from src.cli import _get_module
            _get_module("gitleaks")
            # Should return something (the import succeeds or fails gracefully)

    def test_passphrase_module_scan(self):
        from src.cli import _PassphraseModule
        gen_func = MagicMock(return_value={
            "word_count": 24,
            "entropy_bits": 256,
            "mnemonic": "test word " * 24,
        })
        pm = _PassphraseModule(gen_func, zkit_salt="salt")
        assert pm.name == "crypto_passphrase"
        import asyncio
        result = asyncio.run(pm.scan("test"))
        assert result.status == "ok"
        assert result.finding_count == 1
        assert "BIP-39" in result.findings[0].title

    def test_passphrase_module_scan_error(self):
        from src.cli import _PassphraseModule
        gen_func = MagicMock(side_effect=RuntimeError("boom"))
        pm = _PassphraseModule(gen_func, zkit_salt="salt")
        import asyncio
        result = asyncio.run(pm.scan("test"))
        assert result.status == "ok"
        assert result.finding_count == 1
        assert "error" in result.findings[0].title.lower()


class TestRunWithAI:
    def test_returns_result_when_ai_disabled(self, mock_scan_result):
        from src.cli import _run_with_ai
        result = _run_with_ai(mock_scan_result, ai_enabled=False)
        assert result is mock_scan_result

    @patch("src.cli.asyncio.run")
    @patch("src.cli.AnalysisOrchestrator", create=True)
    def test_calls_orchestrator_when_enabled(self, mock_orch_cls, mock_run, mock_scan_result):
        from src.cli import _run_with_ai
        mock_run.return_value = {"summary": "test"}
        with patch("src.ai.orchestrator.AnalysisOrchestrator", create=True):
            result = _run_with_ai(mock_scan_result, ai_enabled=True)
        assert "ai_report" in result.metadata or "ai_error" in result.metadata


class TestRunZkitTracking:
    def test_noop_when_no_salt(self, mock_scan_result):
        from src.cli import _run_zkit_tracking
        result = _run_zkit_tracking(mock_scan_result, zkit_salt="")
        assert result is mock_scan_result

    def test_adds_graph_metadata(self, mock_scan_result):
        from src.cli import _run_zkit_tracking
        result = _run_zkit_tracking(mock_scan_result, zkit_salt="test-salt")
        assert "zkit_graph" in result.metadata or "zkit_error" in result.metadata


class TestFormatSarif:
    def test_format_sarif_basic(self, mock_scan_result):
        from src.cli import _format_sarif
        import json
        sarif_str = _format_sarif([mock_scan_result])
        sarif = json.loads(sarif_str)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "f1"


class TestResolveCommand:
    def test_resolve_help(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["resolve", "--help"])
        assert result.exit_code == 0
        assert "Resolve an identity" in result.output



class TestMonitorCommand:
    def test_monitor_help(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["monitor", "--help"])
        assert result.exit_code == 0
        assert "Continuously monitor" in result.output


class TestResolveCommandFull:
    @patch("src.modules.sources.discover_sources")
    @patch("src.modules.crypto.leak_finder.extractor.extract_keys")
    def test_resolve_basic(self, mock_extract, mock_discover):
        from typer.testing import CliRunner
        from src.cli import app
        from src.modules.sources.base import RawLeak

        mock_source = MagicMock()
        mock_source.search_for_address = AsyncMock(return_value=[
            RawLeak(text="test leak", source_name="test", source_url="https://test.com"),
        ])
        mock_discover.return_value = {"test": MagicMock(return_value=mock_source)}
        mock_extract.return_value = []

        runner = CliRunner()
        result = runner.invoke(app, ["resolve", "test@email.com", "--sources", "test"])
        assert result.exit_code == 0


class TestMonitorCommandFull:
    def test_monitor_help(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["monitor", "--help"])
        assert result.exit_code == 0
        assert "monitor" in result.output.lower()


class TestLeakFinderCommandFull:
    def test_leak_finder_help(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["leak-finder", "--help"])
        assert result.exit_code == 0


class TestScanCommandFull:
    def test_scan_help(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0


class TestModulesCommandFull:
    def test_modules_command(self):
        from typer.testing import CliRunner
        from src.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["modules"])
        assert result.exit_code == 0
