"""Tests for the PhoneIntelTool aggregator (sources mocked)."""

import os
import tempfile
from unittest.mock import AsyncMock, patch

import pytest

from src.modules.phone_intel import PhoneIntelTool


@pytest.fixture
def db_path() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


class TestPhoneIntelTool:
    async def test_aggregates_all_sources(self, db_path: str):
        tool = PhoneIntelTool(db_path=db_path)
        with patch.object(tool, "_fetch_getcontact", new_callable=AsyncMock) as gc_mock:
            gc_mock.return_value = {"profile": {"name": "Fikri"}, "tags": ["dev"]}
            with patch.object(tool, "_fetch_web", new_callable=AsyncMock) as web_mock:
                web_mock.return_value = {
                    "pages": [{"url": "https://example.com/fikri", "title": "Fikri"}],
                    "count": 1,
                }
                with patch.object(tool, "_fetch_carrier", new_callable=AsyncMock) as car_mock:
                    car_mock.return_value = {
                        "carrier": "Telkomsel",
                        "line_type": "mobile",
                        "country_code": "ID",
                    }
                    with patch.object(tool, "_fetch_truecaller", new_callable=AsyncMock) as tc_mock:
                        tc_mock.return_value = {"data": [{"name": "Fikri Izzudin"}]}
                        result = await tool.search("+6281347241993")

        assert result.status == "ok"
        titles = {f.title for f in result.findings}
        assert "GetContact profile" in titles
        assert "Public pages mentioning this number" in titles
        assert "Carrier and line type" in titles
        assert "Truecaller entry" in titles

        # All sources persisted to the shared DB.

    async def test_non_phone_partial(self, db_path: str):
        tool = PhoneIntelTool(db_path=db_path)
        result = await tool.search("not-a-phone")
        assert result.status == "partial"
        assert len(result.findings) == 0

    async def test_serves_from_db_without_refetch(self, db_path: str):
        from src.modules.phone_intel import db as phone_db

        # Seed a fresh getcontact entry so the source is NOT invoked.
        phone_db.save_lookup(
            db_path,
            "+6281347241993",
            "getcontact",
            {"profile": {"name": "Cached"}, "tags": []},
            ttl_seconds=7 * 24 * 3600,
        )
        tool = PhoneIntelTool(db_path=db_path)
        with patch.object(tool, "_fetch_getcontact", new_callable=AsyncMock) as gc_mock:
            with patch.object(tool, "_fetch_web", new_callable=AsyncMock) as web_mock:
                web_mock.return_value = {"pages": [], "count": 0}
                with patch.object(tool, "_fetch_carrier", new_callable=AsyncMock) as car_mock:
                    car_mock.return_value = None
                    with patch.object(tool, "_fetch_truecaller", new_callable=AsyncMock) as tc_mock:
                        tc_mock.return_value = None
                        result = await tool.search("+6281347241993")

        gc_mock.assert_not_awaited()  # served from DB
        assert result.status == "ok"
        profile = [f for f in result.findings if f.title == "GetContact profile"][0]
        assert profile.raw_data["name"] == "Cached"
