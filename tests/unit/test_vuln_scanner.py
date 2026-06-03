"""Tests for the vulnerability scanner module."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.core.models import Severity
from src.modules.vuln_scanner import VulnScannerTool, SUPPORTED_MODES, _mode_tag


# --- Module-level tests ---


class TestModeTag:
    def test_extracts_type(self):
        assert _mode_tag({"type": "CVE"}) == "cve"

    def test_extracts_category_fallback(self):
        assert _mode_tag({"category": "Web Fingerprint"}) == "web_fingerprint"

    def test_returns_unknown_when_empty(self):
        assert _mode_tag({}) == "unknown"

    def test_replaces_spaces(self):
        assert _mode_tag({"type": "Port Scan"}) == "port_scan"


class TestSupportedModes:
    def test_modes_are_tuples(self):
        assert isinstance(SUPPORTED_MODES, tuple)
        assert "quick" in SUPPORTED_MODES
        assert "full" in SUPPORTED_MODES
        assert "fingerprint" in SUPPORTED_MODES


# --- VulnScannerTool tests ---


class TestVulnScannerToolInit:
    @patch("src.modules.vuln_scanner.subprocess.run")
    def test_init_validates_binary(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="scan4all v1.0")
        tool = VulnScannerTool()
        assert tool.name == "vuln_scanner"
        assert tool.binary_path == "scan4all"

    @patch("src.modules.vuln_scanner.subprocess.run", side_effect=FileNotFoundError)
    def test_init_handles_missing_binary(self, mock_run):
        tool = VulnScannerTool(binary_path="/nonexistent/scan4all")
        assert tool.binary_path == "/nonexistent/scan4all"

    @patch(
        "src.modules.vuln_scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="scan4all", timeout=10),
    )
    def test_init_handles_timeout(self, mock_run):
        tool = VulnScannerTool()
        assert tool.binary_path == "scan4all"


class TestVulnScannerToolScan:
    @pytest.mark.asyncio
    @patch("src.modules.vuln_scanner.subprocess.run")
    async def test_scan_quick_mode(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    "name": "CVE-2024-0001",
                    "vuln_id": "CVE-2024-0001",
                    "description": "Test vulnerability",
                    "severity": "high",
                }
            ),
            stderr="",
        )
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        result = await tool.scan("example.com", mode="quick")
        assert result.module == "vuln_scanner"
        assert result.target == "example.com"
        assert result.status == "ok"
        assert len(result.findings) == 1
        assert result.findings[0].title == "CVE-2024-0001"

    @pytest.mark.asyncio
    @patch("src.modules.vuln_scanner.subprocess.run")
    async def test_scan_fingerprint_mode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        result = await tool.scan("example.com", mode="fingerprint")
        assert result.module == "vuln_scanner"
        assert result.findings == []

    @pytest.mark.asyncio
    @patch("src.modules.vuln_scanner.subprocess.run")
    async def test_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="scan4all", timeout=300)
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        result = await tool.scan("example.com", timeout=300)
        assert result.findings == []

    @pytest.mark.asyncio
    @patch("src.modules.vuln_scanner.subprocess.run")
    async def test_scan_binary_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        result = await tool.scan("example.com")
        assert result.findings == []


class TestVulnScannerToolSearch:
    @pytest.mark.asyncio
    @patch("src.modules.vuln_scanner.subprocess.run")
    async def test_search_calls_scan_quick(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        result = await tool.search("example.com")
        assert result.module == "vuln_scanner"
        # search should use quick mode
        cmd = mock_run.call_args[0][0]
        assert "-scan" in cmd


class TestVulnScannerToolAnalyze:
    @pytest.mark.asyncio
    @patch("src.modules.vuln_scanner.subprocess.run")
    async def test_analyze_delegates_to_scan(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        result = await tool.analyze({"target": "example.com"})
        assert "findings_count" in result
        assert result["target"] == "example.com"


class TestVulnScannerToolLearn:
    @pytest.mark.asyncio
    async def test_learn_raises(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        with pytest.raises(NotImplementedError):
            await tool.learn({})


class TestVulnScannerToolBuildCommand:
    def test_quick_mode(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        cmd = tool._build_command("example.com", "quick")
        assert cmd[0] == "scan4all"
        assert "-t" in cmd
        assert "example.com" in cmd
        assert "pocv2" in cmd

    def test_full_mode(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        cmd = tool._build_command("example.com", "full")
        assert any("portscan" in arg for arg in cmd)

    def test_fingerprint_mode(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        cmd = tool._build_command("example.com", "fingerprint")
        assert "fingerprinthash" in cmd

    def test_invalid_mode_raises(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        with pytest.raises(ValueError, match="Unsupported mode"):
            tool._run_scan("example.com", mode="invalid")


class TestVulnScannerToolParseOutput:
    def test_parses_json_lines(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        tool.name = "vuln_scanner"
        output = json.dumps(
            {
                "name": "CVE-2024-1234",
                "description": "Buffer overflow",
                "severity": "critical",
            }
        )
        findings = tool._parse_output(output, "example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_skips_non_json_lines(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        tool.name = "vuln_scanner"
        output = "not json\n" + json.dumps({"name": "test", "severity": "low"})
        findings = tool._parse_output(output, "example.com")
        assert len(findings) == 1

    def test_empty_output(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        tool.name = "vuln_scanner"
        findings = tool._parse_output("", "example.com")
        assert findings == []

    def test_severity_mapping(self):
        tool = VulnScannerTool.__new__(VulnScannerTool)
        tool.binary_path = "scan4all"
        tool.name = "vuln_scanner"
        for severity_str, expected in [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
            ("unknown", Severity.INFO),
        ]:
            assert tool._map_severity(severity_str) == expected
