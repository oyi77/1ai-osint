from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.modules.free_intel.whatsapp_telegram_check import MessagingIntel


@pytest.mark.asyncio
async def test_check_whatsapp_registered_200():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        client.get = AsyncMock(return_value=resp)

        result = await intel.check_whatsapp("+62 812-3456-7890")
        assert result is True


@pytest.mark.asyncio
async def test_check_whatsapp_registered_redirect():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"location": "https://api.whatsapp.com/send?phone=6281234567890"}
        client.get = AsyncMock(return_value=resp)

        result = await intel.check_whatsapp("081234567890")
        assert result is True


@pytest.mark.asyncio
async def test_check_whatsapp_not_registered_redirect():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"location": "https://wa.me/error"}
        client.get = AsyncMock(return_value=resp)

        result = await intel.check_whatsapp("081234567890")
        assert result is False


@pytest.mark.asyncio
async def test_check_whatsapp_exception():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        client.get = AsyncMock(side_effect=httpx.NetworkError("Network down"))

        result = await intel.check_whatsapp("081234567890")
        assert result is None


@pytest.mark.asyncio
async def test_check_telegram_exists_profile():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'class="tgme_page_title" John Doe'
        client.get = AsyncMock(return_value=resp)

        result = await intel.check_telegram("@johndoe")
        assert result is True


@pytest.mark.asyncio
async def test_check_telegram_exists_group():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "join group or join channel"
        client.get = AsyncMock(return_value=resp)

        result = await intel.check_telegram("johndoe")
        assert result is True


@pytest.mark.asyncio
async def test_check_telegram_not_exists():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "if you have <strong>telegram</strong> installed..."
        client.get = AsyncMock(return_value=resp)

        result = await intel.check_telegram("johndoe")
        assert result is False


@pytest.mark.asyncio
async def test_check_telegram_exception():
    intel = MessagingIntel()
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        client.get = AsyncMock(side_effect=Exception("Timeout"))

        result = await intel.check_telegram("johndoe")
        assert result is None


@pytest.mark.asyncio
async def test_check_all():
    intel = MessagingIntel()
    with (
        patch.object(intel, "check_whatsapp", new_callable=AsyncMock) as mock_wa,
        patch.object(intel, "check_telegram", new_callable=AsyncMock) as mock_tg,
    ):
        mock_wa.return_value = True
        mock_tg.return_value = False

        presence = await intel.check_all(phone="081234567890", username="johndoe")
        assert presence.whatsapp_registered is True
        assert presence.telegram_exists is False
