"""Tests for crypto private key module (scanner + checker)."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from pathlib import Path

from src.modules.crypto.privatekey.scanner import (
    PrivateKeyScanner,
    detect_key_format,
    scan_file,
)
from src.modules.crypto.privatekey.checker import (
    validate_key,
    validate_wif,
    validate_hex_key,
    validate_base58_key,
    validate_pem_key,
    _base58_decode,
)


# --- Scanner tests ---


class TestDetectKeyFormat:
    def test_detect_wif_key(self):
        # WIF uncompressed key (51 chars starting with 5)
        text = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        results = detect_key_format(text)
        formats = [r["format"] for r in results]
        assert "wif" in formats

    def test_detect_hex_key(self):
        text = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        results = detect_key_format(text)
        formats = [r["format"] for r in results]
        assert "hex_32byte" in formats

    def test_detect_hex_0x_prefix(self):
        text = "0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        results = detect_key_format(text)
        formats = [r["format"] for r in results]
        assert "hex_0x" in formats

    def test_detect_pem_key(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END PRIVATE KEY-----"
        )
        results = detect_key_format(pem)
        formats = [r["format"] for r in results]
        assert "pem_private" in formats

    def test_detect_no_keys_in_clean_text(self):
        results = detect_key_format("This is just normal text with no secrets.")
        assert results == []

    def test_results_have_severity(self):
        text = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        results = detect_key_format(text)
        assert all("severity" in r for r in results)


class TestScanFile:
    def test_scan_file_with_key(self, tmp_path):
        p = tmp_path / "test.key"
        p.write_text("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        results = scan_file(p)
        assert len(results) > 0
        assert all("file" in r for r in results)

    def test_scan_file_clean(self, tmp_path):
        p = tmp_path / "clean.txt"
        p.write_text("No secrets here, just regular text.")
        results = scan_file(p)
        assert results == []

    def test_scan_nonexistent_file(self, tmp_path):
        p = tmp_path / "nonexistent.txt"
        results = scan_file(p)
        assert results == []


@pytest.fixture
def scanner():
    return PrivateKeyScanner(zkit_salt="test-salt")


@pytest.fixture
def sample_key_file(tmp_path):
    p = tmp_path / "leaked.key"
    p.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
        "-----END PRIVATE KEY-----\n"
    )
    return tmp_path


class TestPrivateKeyScanner:
    def test_module_name(self, scanner):
        assert scanner.name == "crypto_privatekey"

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, scanner):
        result = await scanner.scan("/nonexistent/path")
        assert result.status == "error"
        assert "does not exist" in result.error

    @pytest.mark.asyncio
    async def test_scan_clean_dir(self, scanner, tmp_path):
        clean_dir = tmp_path / "clean"
        clean_dir.mkdir()
        (clean_dir / "readme.txt").write_text("Hello world")
        result = await scanner.scan(str(clean_dir))
        assert result.status == "ok"
        assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_scan_with_key(self, scanner, sample_key_file):
        result = await scanner.scan(str(sample_key_file))
        assert result.status == "ok"
        assert result.finding_count > 0
        assert result.findings[0].severity.value == "critical"

    @pytest.mark.asyncio
    async def test_analyze_findings(self, scanner, sample_key_file):
        result = await scanner.scan(str(sample_key_file))
        analysis = await scanner.analyze(result)
        assert "total_findings" in analysis
        assert "format_breakdown" in analysis
        assert "has_critical" in analysis

    @pytest.mark.asyncio
    async def test_analyze_list_input(self, scanner, sample_key_file):
        """Analyze accepts a raw list of Finding objects."""
        result = await scanner.scan(str(sample_key_file))
        analysis = await scanner.analyze(result.findings)
        assert "total_findings" in analysis
        assert analysis["total_findings"] == len(result.findings)

    @pytest.mark.asyncio
    async def test_analyze_unsupported_type(self, scanner):
        """Analyze returns error for unsupported data types."""
        analysis = await scanner.analyze("unsupported")
        assert "error" in analysis

    @pytest.mark.asyncio
    async def test_learn_is_noop(self, scanner):
        """learn() accepts feedback without error."""
        await scanner.learn({"false_positive": ["id-1"]})

    @pytest.mark.asyncio
    async def test_search_delegates_to_scan(self, scanner, sample_key_file):
        """search() calls scan() and returns the same result."""
        result = await scanner.search(str(sample_key_file))
        assert result.status == "ok"
        assert result.finding_count > 0


class TestPrivateKeyScannerGithound:
    """Tests for subprocess-based GitHound scanning paths."""

    @pytest.mark.asyncio
    async def test_githound_success(self, tmp_path):
        """GitHound subprocess returns valid JSON findings."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()
        (repo_dir / "test.key").write_text("secret key content")

        scanner = PrivateKeyScanner(githound_path="githound", zkit_salt="test")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            [
                {
                    "rule_id": "wif",
                    "description": "WIF key found",
                    "file": "test.key",
                    "line": 1,
                    "match": "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
                    "commit": "abc123",
                    "author": "dev",
                }
            ]
        )

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = await scanner.scan(str(repo_dir))
            assert result.status == "ok"
            assert result.finding_count > 0
            mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_githound_returns_single_dict(self, tmp_path):
        """GitHound returns a single dict instead of a list."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        scanner = PrivateKeyScanner(githound_path="githound", zkit_salt="test")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "rule_id": "pem_private",
                "description": "PEM key",
                "file": "server.pem",
                "line": 5,
                "match": "-----BEGIN PRIVATE KEY-----",
                "commit": "def456",
                "author": "admin",
            }
        )

        with patch("subprocess.run", return_value=mock_result):
            result = await scanner.scan(str(repo_dir))
            assert result.status == "ok"
            assert result.finding_count == 1

    @pytest.mark.asyncio
    async def test_githound_nonzero_exit_empty_stdout(self, tmp_path):
        """GitHound exits nonzero with empty stdout."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        scanner = PrivateKeyScanner(githound_path="githound", zkit_salt="test")
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = await scanner.scan(str(repo_dir))
            assert result.status == "ok"
            assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_githound_invalid_json(self, tmp_path):
        """GitHound returns invalid JSON."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        scanner = PrivateKeyScanner(githound_path="githound", zkit_salt="test")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "not valid json {{{"

        with patch("subprocess.run", return_value=mock_result):
            result = await scanner.scan(str(repo_dir))
            assert result.status == "ok"
            assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_githound_file_not_found_fallback(self, tmp_path):
        """GitHound binary not found falls back to regex scanning."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()
        (repo_dir / "leaked.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END PRIVATE KEY-----\n"
        )

        scanner = PrivateKeyScanner(
            githound_path="nonexistent-githound", zkit_salt="test"
        )

        with patch("subprocess.run", side_effect=FileNotFoundError("not found")):
            result = await scanner.scan(str(repo_dir))
            assert result.status == "ok"
            # Should have fallen back to regex and found the PEM key
            assert result.finding_count > 0

    @pytest.mark.asyncio
    async def test_githound_timeout(self, tmp_path):
        """GitHound times out, returns empty findings."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        scanner = PrivateKeyScanner(githound_path="githound", zkit_salt="test")

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="githound", timeout=300),
        ):
            result = await scanner.scan(str(repo_dir))
            assert result.status == "ok"
            assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_raw_to_finding_with_alt_keys(self, scanner):
        """_raw_to_finding handles alternate key names (rule-id, File, Line, etc.)."""
        raw = {
            "rule-id": "hex_32byte",
            "File": "secret.env",
            "Line": 42,
            "Match": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "Commit": "abc123",
            "Author": "dev",
            "description": "Hex key found",
        }
        finding = scanner._raw_to_finding(raw, "test-scan-id")
        assert finding is not None
        assert "hex_32byte" in finding.tags
        assert finding.raw_data["file"] == "secret.env"
        assert finding.raw_data["line"] == 42

    def test_detect_encrypted_pem(self):
        """detect_key_format identifies encrypted PEM keys."""
        pem = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END ENCRYPTED PRIVATE KEY-----"
        )
        results = detect_key_format(pem)
        formats = [r["format"] for r in results]
        assert "pem_encrypted" in formats

    def test_detect_rsa_pem(self):
        """detect_key_format identifies RSA PEM keys."""
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END RSA PRIVATE KEY-----"
        )
        results = detect_key_format(pem)
        formats = [r["format"] for r in results]
        assert "pem_private" in formats

    def test_detect_multiple_formats_in_text(self):
        """detect_key_format finds multiple key formats in same text."""
        text = (
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ\n"
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35\n"
        )
        results = detect_key_format(text)
        formats = {r["format"] for r in results}
        assert "wif" in formats
        assert "hex_32byte" in formats

    def test_scan_file_permission_error(self, tmp_path):
        """scan_file handles permission errors gracefully."""
        p = tmp_path / "unreadable.key"
        p.write_text("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            results = scan_file(p)
            assert results == []

    def test_scan_file_os_error(self, tmp_path):
        """scan_file handles OS errors gracefully."""
        p = tmp_path / "broken.key"
        p.write_text("data")
        with patch.object(Path, "read_text", side_effect=OSError("disk error")):
            results = scan_file(p)
            assert results == []

    def test_raw_to_finding_default_rule_id(self, scanner):
        """_raw_to_finding defaults to 'private-key' when no rule_id present."""
        raw = {"description": "unknown key", "file": "test.txt"}
        finding = scanner._raw_to_finding(raw, "test-scan-id")
        assert finding is not None
        assert "private-key" in finding.tags


# --- Checker tests ---


class TestValidateWif:
    def test_valid_uncompressed_wif(self):
        key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        result = validate_wif(key)
        assert result.detected_format == "wif"
        assert result.is_valid_format is True
        assert result.details["compressed"] is False

    def test_valid_compressed_wif_k(self):
        # K-prefixed compressed WIF
        key = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        result = validate_wif(key)
        assert result.detected_format == "wif"
        assert result.is_valid_format is True
        assert result.details["compressed"] is True

    def test_invalid_wif(self):
        result = validate_wif("not-a-valid-key-at-all")
        assert result.is_valid_format is False


class TestValidateHexKey:
    def test_valid_hex_key(self):
        key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        result = validate_hex_key(key)
        assert result.detected_format == "hex"
        assert result.is_valid_format is True
        assert result.details["has_0x_prefix"] is False
        assert result.details["in_valid_range"] is True

    def test_valid_hex_key_with_0x(self):
        key = "0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        result = validate_hex_key(key)
        assert result.is_valid_format is True
        assert result.details["has_0x_prefix"] is True

    def test_invalid_hex_key_too_short(self):
        result = validate_hex_key("abcdef1234")
        assert result.is_valid_format is False

    def test_all_zeros_trivially_weak(self):
        key = "0" * 64
        result = validate_hex_key(key)
        assert result.is_valid_format is True
        assert result.details["trivially_weak"] is True

    def test_out_of_range_key(self):
        # secp256k1 order: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        # Key above curve order
        key = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
        result = validate_hex_key(key)
        assert result.details["in_valid_range"] is False


class TestValidateBase58Key:
    def test_valid_base58_string(self):
        key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        result = validate_base58_key(key)
        assert result.detected_format == "base58"
        assert result.is_valid_format is True

    def test_invalid_base58_with_0_O_l(self):
        # Base58 excludes 0, O, I, l
        key = "0OlI" * 12  # 48 chars, uses invalid chars
        result = validate_base58_key(key)
        assert result.details["uses_base58_alphabet"] is False


class TestValidatePemKey:
    def test_valid_pem(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END PRIVATE KEY-----"
        )
        result = validate_pem_key(pem)
        assert result.detected_format == "pem"
        assert result.is_valid_format is True
        assert result.details["encrypted"] is False

    def test_encrypted_pem(self):
        pem = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END ENCRYPTED PRIVATE KEY-----"
        )
        result = validate_pem_key(pem)
        assert result.is_valid_format is True
        assert result.details["encrypted"] is True

    def test_ec_pem(self):
        pem = (
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END EC PRIVATE KEY-----"
        )
        result = validate_pem_key(pem)
        assert result.is_valid_format is True

    def test_invalid_pem(self):
        result = validate_pem_key("not a pem key")
        assert result.is_valid_format is False


class TestValidateKeyAutoDetect:
    def test_detects_wif(self):
        key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        result = validate_key(key)
        assert result.detected_format == "wif"

    def test_detects_hex(self):
        key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        result = validate_key(key)
        assert result.detected_format == "hex"

    def test_detects_pem(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg\n"
            "-----END PRIVATE KEY-----"
        )
        result = validate_key(pem)
        assert result.detected_format == "pem"

    def test_no_format_matched(self):
        result = validate_key("this is just some text")
        assert result.detected_format is None
        assert result.is_valid_format is False

    def test_to_dict(self):
        key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        result = validate_key(key)
        d = result.to_dict()
        assert "detected_format" in d
        assert "is_valid_format" in d
        assert "details" in d


class TestBase58Decode:
    def test_decode_simple(self):
        # "1" decodes to a single zero byte
        decoded = _base58_decode("1")
        assert decoded == b"\x00"

    def test_decode_roundtrip(self):
        # original bytes removed (unused)
        # Encode manually would be needed for full roundtrip
        # Just test that decode doesn't crash on valid base58
        decoded = _base58_decode("111234")
        assert isinstance(decoded, bytes)

    def test_invalid_char_raises(self):
        with pytest.raises(ValueError, match="Invalid Base58 character"):
            _base58_decode("0OlI")
