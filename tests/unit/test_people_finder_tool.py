"""Tests for PeopleFinderTool wrapper class."""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime

from src.modules.people_finder import PeopleFinderTool
from src.models import Finding, ScanResult, Severity


@pytest.fixture
def tool():
    return PeopleFinderTool(zkit_salt="test-salt")


@pytest.fixture
def mock_subprocess_result():
    result = MagicMock()
    result.stdout = json.dumps({
        "GitHub": {"url": "https://github.com/testuser", "status": "Claimed"},
        "Twitter": {"url": "https://twitter.com/testuser", "status": "Claimed"},
    })
    result.stderr = ""
    result.returncode = 0
    return result


class TestPeopleFinderToolBasics:
    def test_module_name(self, tool):
        assert tool.name == "people_finder"

    def test_description(self, tool):
        assert "social" in tool.description.lower() or "username" in tool.description.lower()

    def test_version(self, tool):
        assert tool.version == "0.1.0"

    def test_pick_tool_sherlock(self, tool):
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/sherlock" if x == "sherlock" else None):
            assert tool._pick_tool() == "sherlock"

    def test_pick_tool_maigret_fallback(self, tool):
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/maigret" if x == "maigret" else None):
            assert tool._pick_tool() == "maigret"

    def test_pick_tool_none(self, tool):
        with patch("shutil.which", return_value=None):
            assert tool._pick_tool() is None


class TestPeopleFinderToolScan:
    @pytest.mark.asyncio
    async def test_scan_no_tool_available(self, tool):
        with patch("shutil.which", return_value=None):
            result = await tool.scan("testuser")

        assert result.status == "error"
        assert result.module == "people_finder"
        assert result.target == "testuser"
        assert "sherlock" in result.error.lower()

    @pytest.mark.asyncio
    async def test_scan_with_sherlock_json_output(self, tool, mock_subprocess_result):
        with patch("shutil.which", return_value="/usr/bin/sherlock"), \
             patch("subprocess.run", return_value=mock_subprocess_result):
            result = await tool.scan("testuser", timeout=30)

        assert result.status == "ok"
        assert result.finding_count == 2
        assert any("GitHub" in f.title for f in result.findings)
        assert any("Twitter" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_scan_with_line_output(self, tool):
        mock_result = MagicMock()
        mock_result.stdout = "https://github.com/testuser\nhttps://twitter.com/testuser"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("shutil.which", return_value="/usr/bin/sherlock"), \
             patch("subprocess.run", return_value=mock_result):
            result = await tool.scan("testuser", timeout=30)

        assert result.status == "ok"
        assert result.finding_count == 2

    @pytest.mark.asyncio
    async def test_scan_timeout(self, tool):
        import subprocess
        with patch("shutil.which", return_value="/usr/bin/sherlock"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="sherlock", timeout=120)):
            result = await tool.scan("testuser")

        assert result.status == "error"
        assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_scan_file_not_found(self, tool):
        with patch("shutil.which", return_value="/usr/bin/sherlock"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            result = await tool.scan("testuser")

        assert result.status == "error"
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_scan_partial_on_bad_returncode(self, tool):
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({
            "GitHub": {"url": "https://github.com/testuser", "status": "Claimed"},
        })
        mock_result.stderr = "some warning"
        mock_result.returncode = 2

        with patch("shutil.which", return_value="/usr/bin/sherlock"), \
             patch("subprocess.run", return_value=mock_result):
            result = await tool.scan("testuser")

        assert result.status == "partial"

    @pytest.mark.asyncio
    async def test_search_delegates_to_scan(self, tool, mock_subprocess_result):
        with patch("shutil.which", return_value="/usr/bin/sherlock"), \
             patch("subprocess.run", return_value=mock_subprocess_result):
            result = await tool.search("testuser", timeout=30)

        assert result.module == "people_finder"
        assert result.finding_count > 0

    @pytest.mark.asyncio
    async def test_scan_uses_maigret_cmd(self, tool):
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({
            "GitHub": {"url": "https://github.com/testuser", "status": "Claimed"},
        })
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("shutil.which", side_effect=lambda x: "/usr/bin/maigret" if x == "maigret" else None), \
             patch("subprocess.run", return_value=mock_result) as mock_run:
            result = await tool.scan("testuser", timeout=30)

        assert result.status == "ok"
        cmd = mock_run.call_args[0][0]
        assert "maigret" in cmd[0]


class TestPeopleFinderToolAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_scan_result(self, tool):
        scan = ScanResult(
            scan_id="test",
            module="people_finder",
            target="testuser",
            findings=[
                Finding(
                    id="f1", module="people_finder", title="Profile: GitHub",
                    raw_data={"site": "GitHub"}, severity=Severity.LOW,
                ),
            ],
        )
        result = await tool.analyze(scan)
        assert result["total_profiles"] == 1
        assert result["username"] == "testuser"
        assert "GitHub" in result["sites_found"]

    @pytest.mark.asyncio
    async def test_analyze_list(self, tool):
        findings = [
            Finding(id="f1", module="m", title="t", raw_data={"site": "X"}, severity=Severity.LOW),
        ]
        result = await tool.analyze(findings)
        assert result["total_profiles"] == 1

    @pytest.mark.asyncio
    async def test_analyze_unsupported(self, tool):
        result = await tool.analyze("bad data")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_learn(self, tool):
        await tool.learn({"corrections": []})
        # No-op, should not raise
