"""Tests for PhoneFinderTool wrapper class."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.models import Finding, ScanResult, Severity
from src.modules.phone_finder import PhoneFinderTool


@pytest.fixture
def tool():
    return PhoneFinderTool(zkit_salt="test-salt", phoneinfoga_url="http://test:3000")


class TestPhoneFinderToolBasics:
    def test_module_name(self, tool):
        assert tool.name == "phone_finder"

    def test_description(self, tool):
        assert "phone" in tool.description.lower()

    def test_version(self, tool):
        assert tool.version == "0.1.0"

    def test_default_url(self):
        t = PhoneFinderTool()
        assert t.phoneinfoga_url == "http://localhost:3000"


class TestPhoneFinderToolScan:
    @pytest.mark.asyncio
    async def test_scan_phoneinfoga_success(self, tool):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "number": {
                "carrier": "Vodafone",
                "country_code": "44",
                "line_type": "mobile",
            },
            "scanners": [],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.modules.phone_finder.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("+447911123456")

        assert result.status == "ok"
        assert result.finding_count >= 1
        assert result.metadata["tool"] == "phoneinfoga"

    @pytest.mark.asyncio
    async def test_scan_phoneinfoga_scam_report(self, tool):
        mock_response = MagicMock()
        mock_response.status_code = 200
        # scanners must be inside the "number" sub-dict since code does:
        #   number_info = data.get("number", data)
        #   scanner_results = number_info.get("scanners", [])
        mock_response.json.return_value = {
            "number": {
                "carrier": "Unknown",
                "scanners": [{"name": "scamdb", "found": True}],
            },
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.modules.phone_finder.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("+14155552671")

        assert result.finding_count >= 2
        scam_findings = [f for f in result.findings if "scam" in f.tags]
        assert len(scam_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_fallback_basic(self, tool):
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.modules.phone_finder.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("+14155552671")

        assert result.status == "partial"
        assert result.metadata["tool"] == "basic"

    @pytest.mark.asyncio
    async def test_scan_cleans_phone_number(self, tool):
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.modules.phone_finder.httpx.AsyncClient", return_value=mock_client):
            result = await tool.scan("(415) 555-2671")

        assert result.metadata["phone"].startswith("+")

    @pytest.mark.asyncio
    async def test_search_delegates_to_scan(self, tool):
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.modules.phone_finder.httpx.AsyncClient", return_value=mock_client):
            result = await tool.search("+14155552671")

        assert result.module == "phone_finder"


class TestPhoneFinderToolAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_scan_result(self, tool):
        scan = ScanResult(
            scan_id="test",
            module="phone_finder",
            target="+14155552671",
            findings=[
                Finding(
                    id="f1",
                    module="phone_finder",
                    title="Phone info",
                    tags=["phone", "carrier"],
                    severity=Severity.INFO,
                ),
                Finding(
                    id="f2",
                    module="phone_finder",
                    title="Scam report",
                    tags=["phone", "scam", "fraud"],
                    severity=Severity.HIGH,
                ),
            ],
        )
        result = await tool.analyze(scan)
        assert result["total_findings"] == 2
        assert result["has_scam_reports"] is True
        assert result["phone"] == "+14155552671"

    @pytest.mark.asyncio
    async def test_analyze_no_scam(self, tool):
        scan = ScanResult(
            scan_id="test",
            module="phone_finder",
            target="+14155552671",
            findings=[
                Finding(
                    id="f1",
                    module="phone_finder",
                    title="Phone info",
                    tags=["phone", "carrier"],
                    severity=Severity.INFO,
                ),
            ],
        )
        result = await tool.analyze(scan)
        assert result["has_scam_reports"] is False

    @pytest.mark.asyncio
    async def test_analyze_list(self, tool):
        findings = [Finding(id="f1", module="m", title="t", tags=["phone"], severity=Severity.INFO)]
        result = await tool.analyze(findings)
        assert result["total_findings"] == 1

    @pytest.mark.asyncio
    async def test_analyze_unsupported(self, tool):
        result = await tool.analyze(42)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_learn(self, tool):
        await tool.learn({"corrections": []})
