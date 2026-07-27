"""Parametrized tests for vendor leak scanner tools — boost coverage from 46% → 70%+."""

from __future__ import annotations

from unittest.mock import patch

import pytest

# All vendor scanner classes that follow the OSINTTool pattern
VENDOR_SCANNERS: list[dict] = [
    {
        "name": "breachdirectory",
        "class_path": "src.vendor.chiasmodon.leak_breachdirectory.BreachDirectoryTool",
        "env_key": "BREACHDIRECTORY_API_KEY",
    },
    {"name": "intelx", "class_path": "src.vendor.chiasmodon.leak_intelx.IntelXTool", "env_key": "INTELX_API_KEY"},
    {"name": "scylla", "class_path": "src.vendor.chiasmodon.leak_scylla.ScyllaTool", "env_key": "SCYLLA_API_KEY"},
    {
        "name": "snusbase",
        "class_path": "src.vendor.chiasmodon.leak_snusbase.SnusbaseTool",
        "env_key": "SNUSBASE_API_KEY",
    },
    {
        "name": "leakcheck",
        "class_path": "src.vendor.chiasmodon.leak_leakcheck.LeakCheckTool",
        "env_key": "LEAKCHECK_API_KEY",
    },
    {"name": "hibp", "class_path": "src.vendor.chiasmodon.hibp.HIBPTool", "env_key": "HIBP_API_KEY"},
    {"name": "shodan", "class_path": "src.vendor.chiasmodon.shodan.ShodanTool", "env_key": "SHODAN_API_KEY"},
    {
        "name": "chiasmodon",
        "class_path": "src.vendor.chiasmodon.chiasmodon.ChiasmodonTool",
        "env_key": "CHIASMODON_TOKEN",
    },
]


def _import_cls(module_path: str):
    """Dynamically import a class from its module path."""
    parts = module_path.split(".")
    mod_path = ".".join(parts[:-1])
    cls_name = parts[-1]
    import importlib

    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


def _make_tool(scanner: dict, has_api_key: bool = True):
    """Create a tool instance and inject API key if needed."""
    cls = _import_cls(scanner["class_path"])
    tool = cls()
    if has_api_key:
        # Inject API key directly (bypass class-level os.environ.get())
        tool.API_KEY = "test-key"  # type: ignore[attr-defined]
    else:
        tool.API_KEY = None  # type: ignore[attr-defined]
    return tool


class TestVendorScannerNoApiKey:
    """All scanners return error dict when API key is missing."""

    @pytest.mark.parametrize("scanner", VENDOR_SCANNERS, ids=[s["name"] for s in VENDOR_SCANNERS])
    def test_search_no_api_key(self, scanner: dict) -> None:
        """Search without API key returns error status."""
        tool = _make_tool(scanner, has_api_key=False)
        result = tool.search("test@example.com")
        assert result["tool"] == scanner["name"]
        # ChiasmodonTool doesn't check API key internally
        if scanner["name"] == "chiasmodon":
            assert result["status"] == "ok"
        else:
            assert result["status"] == "error"
            assert "error" in result


class TestVendorScannerApiError:
    """All HTTP-based scanners handle HTTP errors gracefully."""

    @pytest.mark.parametrize(
        "scanner",
        [s for s in VENDOR_SCANNERS if s["name"] != "chiasmodon"],
        ids=[s["name"] for s in VENDOR_SCANNERS if s["name"] != "chiasmodon"],
    )
    def test_search_http_error(self, scanner: dict) -> None:
        """Search with API key but HTTP 500 returns error."""

        def _raise_for_status():
            import requests

            if mock_response.status_code >= 400:
                raise requests.HTTPError(f"{mock_response.status_code} Error")

        mock_response = type(
            "MockResponse",
            (),
            {
                "status_code": 500,
                "json": lambda self: {},
                "raise_for_status": _raise_for_status,
            },
        )()
        with patch("requests.get", return_value=mock_response), patch("requests.post", return_value=mock_response):
            tool = _make_tool(scanner, has_api_key=True)
            result = tool.search("test@example.com")
        assert result["status"] == "error"
        assert result["tool"] == scanner["name"]


class TestVendorScannerSuccess:
    """All scanners return ok status on successful API call."""

    @pytest.mark.parametrize(
        "scanner",
        [s for s in VENDOR_SCANNERS if s["name"] != "chiasmodon"],
        ids=[s["name"] for s in VENDOR_SCANNERS if s["name"] != "chiasmodon"],
    )
    def test_search_success(self, scanner: dict) -> None:
        """Search with valid API key returns ok."""
        # Handle different response shapes per scanner
        if scanner["name"] == "hibp":
            json_data: list | dict = []
        elif scanner["name"] == "shodan":
            json_data = {"data": []}
        elif scanner["name"] == "intelx":
            json_data = {"records": []}
        else:
            json_data = {"result": []}

        mock_response = type(
            "MockResponse",
            (),
            {"status_code": 200, "json": lambda self: json_data, "raise_for_status": lambda self: None},
        )()
        with patch("requests.get", return_value=mock_response), patch("requests.post", return_value=mock_response):
            tool = _make_tool(scanner, has_api_key=True)
            result = tool.search("test@example.com")
        assert result["status"] == "ok"
        assert result["tool"] == scanner["name"]


class TestVendorScannerStubs:
    """All scanners have scan/analyze/learn stubs."""

    @pytest.mark.parametrize(
        "scanner",
        [s for s in VENDOR_SCANNERS if s["name"] != "chiasmodon"],
        ids=[s["name"] for s in VENDOR_SCANNERS if s["name"] != "chiasmodon"],
    )
    def test_scan_stub(self, scanner: dict) -> None:
        """scan() returns error (not supported) for most scanners."""
        tool = _make_tool(scanner, has_api_key=False)
        result = tool.scan("test")
        assert result["status"] == "error"

    @pytest.mark.parametrize("scanner", VENDOR_SCANNERS, ids=[s["name"] for s in VENDOR_SCANNERS])
    def test_analyze_stub(self, scanner: dict) -> None:
        """analyze() returns a dict."""
        tool = _make_tool(scanner, has_api_key=False)
        result = tool.analyze([])
        assert isinstance(result, dict)
