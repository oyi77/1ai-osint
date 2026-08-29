"""Tests for the phone-intel database layer."""

import os
import tempfile
import time

import pytest

from src.modules.phone_intel import db as phone_db


@pytest.fixture
def db_path() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


class TestPhoneIntelDB:
    def test_empty_returns_none(self, db_path: str):
        assert phone_db.get_lookup(db_path, "+628111", "getcontact") is None

    def test_save_and_get(self, db_path: str):
        phone_db.save_lookup(db_path, "+628111", "carrier", {"carrier": "Telkomsel"})
        entry = phone_db.get_lookup(db_path, "+628111", "carrier")
        assert entry is not None
        assert entry["data"]["carrier"] == "Telkomsel"
        assert entry["source"] == "carrier"

    def test_get_expired(self, db_path: str):
        phone_db.save_lookup(db_path, "+628111", "web", {"pages": []}, ttl_seconds=1)
        time.sleep(1.1)
        entry = phone_db.get_lookup(db_path, "+628111", "web", max_age_seconds=1)
        assert entry is None

    def test_upsert(self, db_path: str):
        phone_db.save_lookup(db_path, "+628111", "getcontact", {"profile": {"a": 1}})
        phone_db.save_lookup(db_path, "+628111", "getcontact", {"profile": {"b": 2}})
        entries = phone_db.query_phone(db_path, "+628111")
        assert len(entries) == 1  # upsert, not duplicate
        assert entries[0]["data"]["profile"]["b"] == 2

    def test_list_phones(self, db_path: str):
        phone_db.save_lookup(db_path, "+6281", "getcontact", {"p": 1})
        phone_db.save_lookup(db_path, "+6281", "web", {"p": 2})
        phone_db.save_lookup(db_path, "+6282", "carrier", {"p": 3})
        phones = phone_db.list_phones(db_path)
        assert len(phones) == 2
        assert phone_db.count(db_path) == 3

    def test_error_status(self, db_path: str):
        phone_db.save_lookup(db_path, "+628111", "truecaller", {}, status="error")
        entry = phone_db.get_lookup(db_path, "+628111", "truecaller")
        assert entry["status"] == "error"
        # error entries are still served (prevent repeated failed fetches)
        assert phone_db.get_lookup(db_path, "+628111", "truecaller", max_age_seconds=3600) is not None

    def test_query_phone_all_sources(self, db_path: str):
        phone_db.save_lookup(db_path, "+6281", "getcontact", {"p": 1})
        phone_db.save_lookup(db_path, "+6281", "web", {"w": 1})
        rows = phone_db.query_phone(db_path, "+6281")
        assert len(rows) == 2
        sources = {r["source"] for r in rows}
        assert sources == {"getcontact", "web"}
