import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.free_intel.bts_intel import BTSIntel


def test_identify_operator():
    intel = BTSIntel()
    # Telkomsel prefix
    assert intel.identify_operator("+62812345678") == ("Telkomsel", 10)
    # Indosat prefix
    assert intel.identify_operator("0815999999") == ("Indosat", 1)
    # Unknown prefix
    assert intel.identify_operator("0800111111") is None


@pytest.mark.asyncio
async def test_analyze_phone():
    intel = BTSIntel()
    result = await intel.analyze_phone("+62812345678")
    assert result.operator == "Telkomsel"
    assert result.mnc == 10


@pytest.mark.asyncio
async def test_get_towers_in_area_no_token():
    with patch.dict(os.environ, {"OPENCELLID_TOKEN": ""}):
        intel = BTSIntel()
        # Ensure it returns empty list if no token
        result = await intel.get_towers_in_area(-6.2, 106.8)
        assert result == []


@pytest.mark.asyncio
async def test_get_towers_in_area_success():
    with patch.dict(os.environ, {"OPENCELLID_TOKEN": "dummy_token"}):
        intel = BTSIntel()
        mock_data = {
            "cells": [
                {
                    "lat": -6.201,
                    "lon": 106.801,
                    "mcc": 510,
                    "mnc": 10,
                    "lac": 123,
                    "cellid": 456,
                    "range": 500,
                    "samples": 10,
                }
            ]
        }
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)

            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = mock_data
            client.get = AsyncMock(return_value=resp)

            result = await intel.get_towers_in_area(-6.2, 106.8)
            assert len(result) == 1
            assert result[0].cellid == 456
            assert result[0].lat == -6.201


@pytest.mark.asyncio
async def test_get_towers_in_area_exception():
    with patch.dict(os.environ, {"OPENCELLID_TOKEN": "dummy_token"}):
        intel = BTSIntel()
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            client.get = AsyncMock(side_effect=Exception("API failure"))

            result = await intel.get_towers_in_area(-6.2, 106.8)
            assert result == []
