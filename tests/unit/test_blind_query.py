"""Unit tests for BlindQueryResolver privacy ranges."""

from unittest.mock import patch

import pytest

from src.modules.data_leaks.breach_checker import BlindQueryResolver


def test_hash_target():
    resolver = BlindQueryResolver()
    # "password" SHA-1 is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    h = resolver.hash_target("password", "sha1")
    assert h == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"

    # "password" SHA-256 is 5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8
    h256 = resolver.hash_target("password", "sha256")
    assert h256 == "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8"


@pytest.mark.asyncio
async def test_check_password_pwned_success():
    resolver = BlindQueryResolver()

    # Target "password"
    # Prefix: 5BAA6
    # Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    mock_body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003\nFFFFF12345:10"

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = mock_body

        is_pwned, count = await resolver.check_password_pwned("password")
        assert is_pwned is True
        assert count == 3303003

        # Verify only 5-character prefix is sent in the URL
        url_called = mock_get.call_args[0][0]
        assert "5BAA6" in url_called
        assert "password" not in url_called.replace("pwnedpasswords", "")


@pytest.mark.asyncio
async def test_check_password_pwned_miss():
    resolver = BlindQueryResolver()
    mock_body = "ABCDEB93F3F0682250B6CF8331B7EE68FD8:1"

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = mock_body

        is_pwned, count = await resolver.check_password_pwned("password")
        assert is_pwned is False
        assert count == 0
