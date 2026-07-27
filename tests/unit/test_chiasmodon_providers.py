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
        mock_resp.json.return_value = {"data": {"attributes": {"last_analysis_stats": {}}}}
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
        mock_resp.json.return_value = {"archived_snapshots": {"closest": {"url": "http://web.archive.org/..."}}}
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
    def test_sherlock_success(self, mock_run, mock_tmp, mock_open, _isfile, _size, _unlink):
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

        mock_run.return_value = MagicMock(returncode=0, stdout='{"github": "https://github.com/user"}', stderr="")
        result = MaigretProvider().search("user")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_holehe_success(self, mock_run):
        from src.vendor.chiasmodon.providers.holehe import HoleheProvider

        mock_run.return_value = MagicMock(returncode=0, stdout='{"twitter": true}', stderr="")
        result = HoleheProvider().search("test@example.com")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_h8mail_success(self, mock_run):
        from src.vendor.chiasmodon.providers.h8mail import H8mailProvider

        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": []}', stderr="")
        result = H8mailProvider().search("test@example.com")
        assert isinstance(result, dict)

    @patch("subprocess.run")
    def test_amass_success(self, mock_run):
        from src.vendor.chiasmodon.providers.amass import AmassProvider

        mock_run.return_value = MagicMock(returncode=0, stdout='{"name": "sub.example.com"}', stderr="")
        result = AmassProvider().search("example.com")
        assert isinstance(result, list)

    @patch("subprocess.run")
    def test_exiftool_success(self, mock_run):
        from src.vendor.chiasmodon.providers.exiftool import ExifToolProvider

        mock_run.return_value = MagicMock(returncode=0, stdout='[{"SourceFile": "test.jpg"}]', stderr="")
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


class TestDatasploitProvider:
    """Test Datasploit CLI wrapper."""

    @patch("subprocess.run")
    def test_search_success(self, mock_run):
        from src.vendor.chiasmodon.providers.datasploit import DatasploitProvider

        mock_run.return_value = MagicMock(returncode=0, stdout='{"domain": "example.com", "emails": []}', stderr="")
        result = DatasploitProvider().search("example.com")
        assert isinstance(result, dict)
        assert result["domain"] == "example.com"

    @patch("subprocess.run")
    def test_search_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.datasploit import DatasploitProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="tool error")
        result = DatasploitProvider().search("example.com")
        assert "error" in result
        assert "tool error" in result["error"]

    @patch("subprocess.run")
    def test_search_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.datasploit import DatasploitProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = DatasploitProvider().search("example.com")
        assert "error" in result
        assert result["error"] == "Datasploit failed"

    @patch("subprocess.run", side_effect=OSError("binary not found"))
    def test_search_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.datasploit import DatasploitProvider

        result = DatasploitProvider().search("example.com")
        assert "error" in result
        assert "binary not found" in result["error"]


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


class TestSpiderFootProvider:
    """Test SpiderFoot CLI wrapper."""

    @patch("subprocess.run")
    def test_search_success(self, mock_run):
        from src.vendor.chiasmodon.providers.spiderfoot import SpiderFootProvider

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"type": "EMAIL", "module": "sfp_spider", "data": "test@example.com"}]',
            stderr="",
        )
        result = SpiderFootProvider().search("example.com")
        assert isinstance(result, list)

    @patch("subprocess.run")
    def test_search_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.spiderfoot import SpiderFootProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="spiderfoot error")
        result = SpiderFootProvider().search("example.com")
        assert "error" in result

    @patch("subprocess.run")
    def test_search_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.spiderfoot import SpiderFootProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = SpiderFootProvider().search("example.com")
        assert "error" in result
        assert result["error"] == "SpiderFoot failed"

    @patch("subprocess.run", side_effect=FileNotFoundError("sf.py not found"))
    def test_search_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.spiderfoot import SpiderFootProvider

        result = SpiderFootProvider().search("example.com")
        assert "error" in result
        assert "not found" in result["error"]


class TestTheHarvesterProvider:
    """Test TheHarvester CLI wrapper."""

    @patch("subprocess.run")
    def test_search_success(self, mock_run):
        from src.vendor.chiasmodon.providers.theharvester import TheHarvesterProvider

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="[*] Emails found: test@example.com\n[*] Hosts found: example.com",
            stderr="",
        )
        result = TheHarvesterProvider().search("example.com")
        assert isinstance(result, dict)
        assert "raw" in result

    @patch("subprocess.run")
    def test_search_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.theharvester import TheHarvesterProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="harvester error")
        result = TheHarvesterProvider().search("example.com")
        assert "error" in result

    @patch("subprocess.run")
    def test_search_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.theharvester import TheHarvesterProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = TheHarvesterProvider().search("example.com")
        assert "error" in result
        assert result["error"] == "theHarvester failed"

    @patch("subprocess.run", side_effect=PermissionError("not executable"))
    def test_search_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.theharvester import TheHarvesterProvider

        result = TheHarvesterProvider().search("example.com")
        assert "error" in result
        assert "not executable" in result["error"]


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
    def test_amass_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.amass import AmassProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="enum failed")
        result = AmassProvider().search("example.com")
        assert isinstance(result, dict)
        assert "error" in result
        assert "enum failed" in result["error"]

    @patch("subprocess.run", side_effect=RuntimeError("amass crash"))
    def test_amass_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.amass import AmassProvider

        result = AmassProvider().search("example.com")
        assert isinstance(result, dict)
        assert "error" in result
        assert "amass crash" in result["error"]

    @patch("subprocess.run")
    def test_amass_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.amass import AmassProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = AmassProvider().search("example.com")
        assert "error" in result
        assert result["error"] == "Amass failed"

    @patch("subprocess.run")
    def test_exiftool_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.exiftool import ExifToolProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="no such file")
        result = ExifToolProvider().search("missing.jpg")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run", side_effect=OSError("exiftool not installed"))
    def test_exiftool_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.exiftool import ExifToolProvider

        result = ExifToolProvider().search("test.jpg")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run")
    def test_exiftool_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.exiftool import ExifToolProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = ExifToolProvider().search("test.jpg")
        assert "error" in result
        assert result["error"] == "ExifTool failed"

    @patch("subprocess.run")
    def test_h8mail_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.h8mail import H8mailProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="h8mail error")
        result = H8mailProvider().search("test@example.com")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run", side_effect=FileNotFoundError("h8mail not found"))
    def test_h8mail_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.h8mail import H8mailProvider

        result = H8mailProvider().search("test@example.com")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run")
    def test_h8mail_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.h8mail import H8mailProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = H8mailProvider().search("test@example.com")
        assert "error" in result
        assert result["error"] == "h8mail failed"

    @patch("subprocess.run")
    def test_holehe_error_returncode(self, mock_run):
        from src.vendor.chiasmodon.providers.holehe import HoleheProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="holehe failed")
        result = HoleheProvider().search("test@example.com")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run", side_effect=Exception("holehe crash"))
    def test_holehe_exception(self, mock_run):
        from src.vendor.chiasmodon.providers.holehe import HoleheProvider

        result = HoleheProvider().search("test@example.com")
        assert isinstance(result, dict)
        assert "error" in result

    @patch("subprocess.run")
    def test_holehe_empty_stderr(self, mock_run):
        from src.vendor.chiasmodon.providers.holehe import HoleheProvider

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = HoleheProvider().search("test@example.com")
        assert "error" in result
        assert result["error"] == "Holehe failed"

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
