"""Tests for chiasmodon providers — API and CLI wrappers."""

from unittest.mock import MagicMock, patch


class TestHIBPProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.haveibeenpwned import (
            HaveIBeenPwnedProvider,
        )

        provider = HaveIBeenPwnedProvider(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"Name": "Breach1"}]
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("test@example.com")
        assert isinstance(result, list)

    def test_search_not_found(self):
        from src.vendor.chiasmodon.providers.haveibeenpwned import (
            HaveIBeenPwnedProvider,
        )

        provider = HaveIBeenPwnedProvider(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("clean@example.com")
        assert result == []


class TestShodanProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.shodan import ShodanProvider

        provider = ShodanProvider(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ip_str": "1.2.3.4", "ports": [80]}
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("1.2.3.4")
        assert "ip_str" in result


class TestVirusTotalProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.virustotal import VirusTotalProvider

        provider = VirusTotalProvider(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {}}}
        }
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("https://example.com")
        assert "data" in result


class TestAbuseIPDBProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.abuseipdb import AbuseIPDBProvider

        provider = AbuseIPDBProvider(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"ipAddress": "1.2.3.4"}}
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("1.2.3.4")
        assert "data" in result


class TestWhoisXMLProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.whoisxml import WhoisXMLProvider

        provider = WhoisXMLProvider(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"WhoisRecord": {"domainName": "example.com"}}
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("example.com")
        assert "WhoisRecord" in result


class TestCrtShProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.crtsh import CrtShProvider

        provider = CrtShProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"name_value": "example.com"}]
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("example.com")
        assert isinstance(result, list)


class TestWaybackProvider:
    def test_search_success(self):
        from src.vendor.chiasmodon.providers.wayback import WaybackProvider

        provider = WaybackProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "archived_snapshots": {"closest": {"url": "http://web.archive.org/..."}}
        }
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("example.com")
        assert "archived_snapshots" in result


class TestSocialProvider:
    def test_search_returns_dict(self):
        from src.vendor.chiasmodon.providers.social import SocialProvider

        provider = SocialProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            result = provider.search("testuser")
        assert isinstance(result, dict)
        assert "twitter" in result


class TestCLIProviders:
    """Test CLI-wrapping providers with mocked subprocess."""

    @patch("os.unlink")
    @patch("os.path.getsize", return_value=64)
    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    @patch("tempfile.NamedTemporaryFile")
    @patch("subprocess.run")
    def test_sherlock_success(
        self, mock_run, mock_tmp, mock_open, _isfile, _size, _unlink
    ):
        from src.vendor.chiasmodon.providers.sherlock import SherlockProvider

        mock_tmp.return_value.__enter__.return_value.name = "/tmp/out.json"
        mock_open.return_value.__enter__.return_value.read.return_value = (
            '{"twitter": {"status": "Claimed", "url": "https://twitter.com/user"}}'
        )
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = SherlockProvider().search("user")
        assert isinstance(result, dict)
        assert "twitter" in result

    @patch("subprocess.run")
    def test_maigret_success(self, mock_run):
        from src.vendor.chiasmodon.providers.maigret import MaigretProvider

        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"github": "https://github.com/user"}', stderr=""
        )
        result = MaigretProvider().search("user")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_holehe_success(self, mock_run):
        from src.vendor.chiasmodon.providers.holehe import HoleheProvider

        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"twitter": true}', stderr=""
        )
        result = HoleheProvider().search("test@example.com")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_h8mail_success(self, mock_run):
        from src.vendor.chiasmodon.providers.h8mail import H8mailProvider

        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"results": []}', stderr=""
        )
        result = H8mailProvider().search("test@example.com")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_amass_success(self, mock_run):
        from src.vendor.chiasmodon.providers.amass import AmassProvider

        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"name": "sub.example.com"}', stderr=""
        )
        result = AmassProvider().search("example.com")
        assert isinstance(result, list)

    @patch("subprocess.run")
    def test_exiftool_success(self, mock_run):
        from src.vendor.chiasmodon.providers.exiftool import ExifToolProvider

        mock_run.return_value = MagicMock(
            returncode=0, stdout='[{"SourceFile": "test.jpg"}]', stderr=""
        )
        result = ExifToolProvider().search("test.jpg")
        assert isinstance(result, list)

    @patch("os.path.getsize", return_value=0)
    @patch("os.path.isfile", return_value=True)
    @patch("subprocess.run")
    def test_cli_provider_error(self, mock_run, _isfile, _size):
        from src.vendor.chiasmodon.providers.sherlock import SherlockProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
        result = SherlockProvider().search("user")
        assert "error" in result
