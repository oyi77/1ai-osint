import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.free_intel.github_intel import GitHubIntel


@pytest.mark.asyncio
async def test_extract_full_profile():
    intel = GitHubIntel()
    mock_profile = {
        "name": "Test User",
        "email": "test@example.com",
        "company": "TestCo",
        "location": "Jakarta",
        "bio": "Dev",
        "blog": "https://test.com",
        "twitter_username": "testuser",
        "avatar_url": "https://avatar.com/1.jpg",
        "public_repos": 10,
        "followers": 50,
        "following": 20,
        "created_at": "2020-01-01T00:00:00Z",
    }
    mock_events = [
        {
            "type": "PushEvent",
            "payload": {"commits": [{"author": {"email": "real@email.com"}}]},
        }
    ]
    mock_repos = [{"name": "project-1"}, {"name": "project-2"}]

    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

        profile_resp = MagicMock(status_code=200)
        profile_resp.json.return_value = mock_profile
        events_resp = MagicMock(status_code=200)
        events_resp.json.return_value = mock_events
        repos_resp = MagicMock(status_code=200)
        repos_resp.json.return_value = mock_repos

        client.get = AsyncMock(side_effect=[profile_resp, events_resp, repos_resp])

        result = await intel.extract("testuser")

    assert result.full_name == "Test User"
    assert result.email == "test@example.com"
    assert result.company == "TestCo"
    assert result.location == "Jakarta"
    assert "real@email.com" in result.commit_emails
    assert "project-1" in result.repo_names


@pytest.mark.asyncio
async def test_extract_handles_404():
    intel = GitHubIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        resp = MagicMock(status_code=404)
        client.get = AsyncMock(return_value=resp)
        result = await intel.extract("nonexistent")
    assert result.username == "nonexistent"
    assert result.full_name == ""


@pytest.mark.asyncio
async def test_noreply_emails_filtered():
    intel = GitHubIntel()
    mock_events = [
        {
            "type": "PushEvent",
            "payload": {
                "commits": [
                    {"author": {"email": "12345+user@users.noreply.github.com"}},
                    {"author": {"email": "real@company.com"}},
                ]
            },
        }
    ]
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        profile_resp = MagicMock(status_code=404)
        events_resp = MagicMock(status_code=200)
        events_resp.json.return_value = mock_events
        repos_resp = MagicMock(status_code=404)
        client.get = AsyncMock(side_effect=[profile_resp, events_resp, repos_resp])
        result = await intel.extract("user")
    assert "real@company.com" in result.commit_emails
    assert not any("noreply" in e for e in result.commit_emails)


@pytest.mark.asyncio
async def test_extract_with_token():
    intel = GitHubIntel()
    intel.token = "fake_github_token"
    headers = intel._headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer fake_github_token"


@pytest.mark.asyncio
async def test_extract_exceptions():
    intel = GitHubIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        client.get.side_effect = Exception("API error")
        result = await intel.extract("testuser")

    assert result.username == "testuser"
    assert result.full_name == ""
    assert len(result.commit_emails) == 0
    assert len(result.repo_names) == 0
