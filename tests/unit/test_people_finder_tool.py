"""Tests for PeopleFinderTool wrapper class."""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone

from src.modules.people_finder import PeopleFinderTool
from src.core.models import Finding, ScanResult, Severity


@pytest.fixture
def tool():
    return PeopleFinderTool(zkit_salt="test-salt")


@pytest.fixture
def mock_subprocess_result():
    result = MagicMock()
    result.stdout = json.dumps(
        {
            "GitHub": {"url": "https://github.com/testuser", "status": "Claimed"},
            "Twitter": {"url": "https://twitter.com/testuser", "status": "Claimed"},
        }
    )
    result.stderr = ""
    result.returncode = 0
    return result


class TestPeopleFinderToolBasics:
    def test_module_name(self, tool):
        assert tool.name == "people_finder"

    def test_description(self, tool):
        assert (
            "social" in tool.description.lower()
            or "username" in tool.description.lower()
        )

    def test_version(self, tool):
        assert tool.version == "0.1.0"

    def test_pick_tool_sherlock(self, tool):
        with patch(
            "shutil.which",
            side_effect=lambda x: "/usr/bin/sherlock" if x == "sherlock" else None,
        ):
            assert tool._pick_tool() == "sherlock"

    def test_pick_tool_maigret_fallback(self, tool):
        with patch(
            "shutil.which",
            side_effect=lambda x: "/usr/bin/maigret" if x == "maigret" else None,
        ):
            assert tool._pick_tool() == "maigret"

    def test_pick_tool_none(self, tool):
        with patch("shutil.which", return_value=None):
            assert tool._pick_tool() is None


class TestPeopleFinderToolScan:
    @pytest.mark.asyncio
    async def test_scan_no_tool_available(self, tool):
        with patch.object(tool._search, "_get_providers", return_value={}):
            result = await tool.scan("testuser")

        assert result.status == "ok"
        assert result.module == "people_finder"
        assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_scan_with_sherlock_json_output(self, tool):
        mock_sr = ScanResult(
            scan_id="t",
            module="people_finder",
            target="testuser",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="people_finder",
                    title="Profile: GitHub/testuser",
                    description="",
                    severity=Severity.INFO,
                    raw_data={"platform": "GitHub"},
                ),
                Finding(
                    id="f2",
                    module="people_finder",
                    title="Profile: Twitter/testuser",
                    description="",
                    severity=Severity.INFO,
                    raw_data={"platform": "Twitter"},
                ),
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        with patch.object(
            tool._search, "scan", new_callable=AsyncMock, return_value=mock_sr
        ):
            result = await tool.scan("testuser", timeout=30)

        assert result.status == "ok"
        assert result.finding_count == 2

    @pytest.mark.asyncio
    async def test_scan_with_line_output(self, tool):
        mock_sr = ScanResult(
            scan_id="t",
            module="people_finder",
            target="testuser",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="people_finder",
                    title="Profile found",
                    description="https://github.com/testuser",
                    severity=Severity.INFO,
                    raw_data={"url": "https://github.com/testuser"},
                ),
                Finding(
                    id="f2",
                    module="people_finder",
                    title="Profile found",
                    description="https://twitter.com/testuser",
                    severity=Severity.INFO,
                    raw_data={"url": "https://twitter.com/testuser"},
                ),
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        with patch.object(
            tool._search, "scan", new_callable=AsyncMock, return_value=mock_sr
        ):
            result = await tool.scan("testuser", timeout=30)

        assert result.status == "ok"
        assert result.finding_count == 2

    @pytest.mark.asyncio
    async def test_scan_timeout(self, tool):
        mock_sr = ScanResult(
            scan_id="t",
            module="people_finder",
            target="testuser",
            status="error",
            error="People finder scan timed out",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        with patch.object(
            tool._search, "scan", new_callable=AsyncMock, return_value=mock_sr
        ):
            result = await tool.scan("testuser")

        assert result.status == "error"
        assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_scan_file_not_found(self, tool):
        mock_sr = ScanResult(
            scan_id="t",
            module="people_finder",
            target="testuser",
            status="error",
            error="sherlock not found",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        with patch.object(
            tool._search, "scan", new_callable=AsyncMock, return_value=mock_sr
        ):
            result = await tool.scan("testuser")

        assert result.status == "error"
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_scan_partial_on_bad_returncode(self, tool):
        mock_sr = ScanResult(
            scan_id="t",
            module="people_finder",
            target="testuser",
            status="partial",
            findings=[
                Finding(
                    id="f1",
                    module="people_finder",
                    title="GitHub",
                    description="",
                    severity=Severity.INFO,
                    raw_data={},
                )
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        with patch.object(
            tool._search, "scan", new_callable=AsyncMock, return_value=mock_sr
        ):
            result = await tool.scan("testuser")

        assert result.status == "partial"

    @pytest.mark.asyncio
    async def test_search_delegates_to_scan(self, tool):
        mock_sr = ScanResult(
            scan_id="t",
            module="people_finder",
            target="testuser",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="people_finder",
                    title="x",
                    description="",
                    severity=Severity.INFO,
                    raw_data={},
                )
            ],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        with patch.object(
            tool._search, "scan", new_callable=AsyncMock, return_value=mock_sr
        ):
            result = await tool.search("testuser", timeout=30)

        assert result.module == "people_finder"
        assert result.finding_count > 0

    @pytest.mark.asyncio
    async def test_scan_delegates_to_search_engine(self, tool):
        with patch.object(tool._search, "scan", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ScanResult(
                scan_id="t",
                module="people_finder",
                target="u",
                status="ok",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            await tool.scan("testuser")
            mock_scan.assert_awaited_once()


class TestPeopleFinderToolAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_scan_result(self, tool):
        scan = ScanResult(
            scan_id="test",
            module="people_finder",
            target="testuser",
            findings=[
                Finding(
                    id="f1",
                    module="people_finder",
                    title="Profile: GitHub",
                    raw_data={"site": "GitHub"},
                    severity=Severity.LOW,
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
            Finding(
                id="f1",
                module="m",
                title="t",
                raw_data={"site": "X"},
                severity=Severity.LOW,
            ),
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
