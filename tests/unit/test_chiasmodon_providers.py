"""Tests for chiasmodon providers — API and CLI wrappers."""

from unittest.mock import MagicMock, patch


class TestCLIProviders:
    """Test CLI-wrapping providers with mocked subprocess."""

    @patch(
        "src.vendor.chiasmodon.providers.sherlock.SherlockProvider._parse_csv",
        return_value={"twitter": {"status": "Claimed", "url": "https://twitter.com/user"}},
    )
    @patch("os.path.getsize", return_value=64)
    @patch("os.path.isfile", return_value=True)
    @patch("subprocess.run")
    def test_sherlock_success(self, mock_run, _isfile, _size, mock_parse):
        from src.vendor.chiasmodon.providers.sherlock import SherlockProvider

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = SherlockProvider().search("user")
        assert isinstance(result, dict)
        assert "twitter" in result
        mock_parse.assert_called_once()

    def test_parse_csv_real_file(self):
        import csv
        import os
        import tempfile

        from src.vendor.chiasmodon.providers.sherlock import SherlockProvider

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "user.csv")
            with open(path, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["name", "exists", "url_user", "url_main", "username", "http_status", "response_time_s"])
                w.writerow(["twitter", "Claimed", "https://twitter.com/user", "", "user", "200", "0.5"])
                w.writerow(["", "Claimed", "", "", "", "", ""])
            sites = SherlockProvider._parse_csv(path)
            assert "twitter" in sites
            assert sites["twitter"]["status"] == "claimed"
            assert sites["twitter"]["url"] == "https://twitter.com/user"

    @patch("subprocess.run")
    def test_maigret_success(self, mock_run):
        from src.vendor.chiasmodon.providers.maigret import MaigretProvider

        mock_run.return_value = MagicMock(returncode=0, stdout='{"github": "https://github.com/user"}', stderr="")
        result = MaigretProvider().search("user")
        assert isinstance(result, dict)

    @patch("os.path.getsize", return_value=0)
    @patch("os.path.isfile", return_value=True)
    @patch("subprocess.run")
    def test_cli_provider_error(self, mock_run, _isfile, _size):
        from src.vendor.chiasmodon.providers.sherlock import SherlockProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
        result = SherlockProvider().search("user")
        assert "error" in result


class TestPhoneInfogaProvider:
    """Test PhoneInfoga CLI wrapper."""

    @patch("subprocess.run")
    def test_search_success(self, mock_run):
        from src.vendor.chiasmodon.providers.phoneinfoga import PhoneInfogaProvider

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"valid": true, "country": "US", "carrier": "Verizon"}',
            stderr="",
        )
        result = PhoneInfogaProvider().search("+14155551234")
        assert isinstance(result, dict)
        assert result["valid"] is True

    @patch("subprocess.run")
    def test_search_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.phoneinfoga import PhoneInfogaProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="scan failed")
        result = PhoneInfogaProvider().search("+14155551234")
        assert "error" in result
        assert "scan failed" in result["error"]

    @patch("subprocess.run")
    def test_search_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.phoneinfoga import PhoneInfogaProvider

        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="")
        result = PhoneInfogaProvider().search("+14155551234")
        assert "error" in result
        assert result["error"] == "PhoneInfoga failed"

    @patch("subprocess.run", side_effect=RuntimeError("timeout"))
    def test_search_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.phoneinfoga import PhoneInfogaProvider

        result = PhoneInfogaProvider().search("+14155551234")
        assert "error" in result
        assert "timeout" in result["error"]


class TestWhatsMyNameProvider:
    """Test WhatsMyName CLI wrapper."""

    @patch("subprocess.run")
    def test_search_success(self, mock_run):
        from src.vendor.chiasmodon.providers.whatsmyname import WhatsMyNameProvider

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"sites": [{"name": "GitHub", "url_user": "https://github.com/testuser"}]}',
            stderr="",
        )
        result = WhatsMyNameProvider().search("testuser")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_search_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.whatsmyname import WhatsMyNameProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="rate limited")
        result = WhatsMyNameProvider().search("testuser")
        assert "error" in result

    @patch("subprocess.run")
    def test_search_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.whatsmyname import WhatsMyNameProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = WhatsMyNameProvider().search("testuser")
        assert "error" in result
        assert result["error"] == "WhatsMyName failed"

    @patch("subprocess.run", side_effect=Exception("unexpected crash"))
    def test_search_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.whatsmyname import WhatsMyNameProvider

        result = WhatsMyNameProvider().search("testuser")
        assert "error" in result
        assert "unexpected crash" in result["error"]


class TestCLIProviderErrorPaths:
    """Error path tests for CLI-wrapping providers at 77% coverage."""

    @patch("subprocess.run")
    def test_maigret_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.maigret import MaigretProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="maigret error")
        result = MaigretProvider().search("testuser")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run", side_effect=RuntimeError("maigret timeout"))
    def test_maigret_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.maigret import MaigretProvider

        result = MaigretProvider().search("testuser")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run")
    def test_maigret_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.maigret import MaigretProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = MaigretProvider().search("testuser")
        assert "error" in result
        assert result["error"] == "Maigret failed"
