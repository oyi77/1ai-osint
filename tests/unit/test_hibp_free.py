import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.free_intel.hibp_free import HIBPIntel


@pytest.mark.asyncio
async def test_check_email_with_api_key_success():
    with patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"}):
        intel = HIBPIntel()
        mock_data = [
            {
                "Name": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "DataClasses": ["Email", "Password"],
                "Description": "Hack",
                "IsVerified": True,
                "PwnCount": 150000000,
            }
        ]
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = mock_data
            client.get = AsyncMock(return_value=resp)

            result = await intel.check_email("test@example.com")
            assert len(result) == 1
            assert result[0].name == "Adobe"
            assert result[0].domain == "adobe.com"


@pytest.mark.asyncio
async def test_check_email_with_api_key_404():
    with patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"}):
        intel = HIBPIntel()
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

            resp = MagicMock()
            resp.status_code = 404
            client.get = AsyncMock(return_value=resp)

            result = await intel.check_email("clean@example.com")
            assert result == []


@pytest.mark.asyncio
async def test_check_email_with_api_key_exception():
    with patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"}):
        intel = HIBPIntel()
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            client.get = AsyncMock(side_effect=Exception("API failure"))

            result = await intel.check_email("test@example.com")
            assert result == []


@pytest.mark.asyncio
async def test_check_email_no_api_key_free_success():
    with patch.dict(os.environ, {"HIBP_API_KEY": ""}):
        intel = HIBPIntel()
        mock_breaches = [
            {
                "Name": "Tokopedia",
                "Domain": "tokopedia.com",
                "BreachDate": "2020-04-17",
                "DataClasses": ["Email", "Name"],
                "IsVerified": True,
                "PwnCount": 91000000,
            },
            {
                "Name": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "DataClasses": ["Email"],
                "IsVerified": True,
                "PwnCount": 150000000,
            },
        ]
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = mock_breaches
            client.get = AsyncMock(return_value=resp)

            result = await intel.check_email("test@example.com")
            assert len(result) == 1
            assert result[0].name == "Tokopedia"


@pytest.mark.asyncio
async def test_check_email_no_api_key_free_exception():
    with patch.dict(os.environ, {"HIBP_API_KEY": ""}):
        intel = HIBPIntel()
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            client.get = AsyncMock(side_effect=Exception("Free API failure"))

            result = await intel.check_email("test@example.com")
            assert result == []
