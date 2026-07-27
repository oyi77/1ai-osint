"""Tests for Gravatar Intelligence module."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.modules.free_intel.gravatar_intel import GravatarIntel


@pytest.mark.asyncio
async def test_gravatar_lookup_success():
    intel = GravatarIntel()
    email = "test@example.com"
    email_hash = "55502f40dc8b7c769880b10874abc9d0"  # md5 hash of test@example.com

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "entry": [
            {
                "displayName": "Test User",
                "preferredUsername": "testuser",
                "profileUrl": "https://gravatar.com/testuser",
                "thumbnailUrl": "https://gravatar.com/avatar/testuser.png",
                "aboutMe": "Just a test account",
                "currentLocation": "Earth",
                "accounts": [
                    {
                        "domain": "github.com",
                        "url": "https://github.com/testuser",
                        "username": "testuser",
                    }
                ],
            }
        ]
    }

    # httpx.AsyncClient is used as a context manager, so entering it returns mock_client
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        profile = await intel.lookup(email)

        assert profile is not None
        assert profile.email_hash == email_hash
        assert profile.display_name == "Test User"
        assert profile.profile_url == "https://gravatar.com/testuser"
        assert profile.photo_url == "https://gravatar.com/avatar/testuser.png"
        assert profile.about_me == "Just a test account"
        assert profile.current_location == "Earth"
        assert len(profile.verified_accounts) == 1
        assert profile.verified_accounts[0]["domain"] == "github.com"
        assert profile.verified_accounts[0]["username"] == "testuser"
        mock_client.get.assert_called_once_with(f"https://en.gravatar.com/{email_hash}.json")


@pytest.mark.asyncio
async def test_gravatar_lookup_not_found():
    intel = GravatarIntel()
    email = "missing@example.com"

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        profile = await intel.lookup(email)
        assert profile is None


@pytest.mark.asyncio
async def test_gravatar_lookup_exception():
    intel = GravatarIntel()
    email = "error@example.com"

    mock_client = AsyncMock()
    mock_client.get.side_effect = httpx.ConnectError("Connection failed")

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client_class.return_value.__aenter__.return_value = mock_client
        profile = await intel.lookup(email)
        assert profile is None
