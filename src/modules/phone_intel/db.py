"""Local phone-intel SQLite store.

Aggregates phone lookups from every source (getcontact, carrier, web search,
truecaller, ...) into one queryable database so limited/quota-billed sources
are only called once per phone within their TTL. Uses stdlib sqlite3.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_DEFAULT_DB = "state/phone_intel.db"
_lock = threading.Lock()
_default_path: str | None = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS phone_lookups (
    phone      TEXT NOT NULL,
    source     TEXT NOT NULL,
    data       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'ok',
    fetched_at TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (phone, source)
);
CREATE INDEX IF NOT EXISTS idx_phone_lookups_phone ON phone_lookups(phone);
"""


def default_db_path() -> str:
    """Return the default DB path (env PHONE_INTEL_DB or state/phone_intel.db)."""
    global _default_path
    if _default_path is None:
        import os

        _default_path = os.environ.get("PHONE_INTEL_DB") or _DEFAULT_DB
    return _default_path


def set_default_db_path(path: str) -> None:
    """Override the default DB path (used by tests)."""
    global _default_path
    _default_path = path


def _connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)  # multi-statement schema
    conn.commit()
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_lookup(
    db_path: str,
    phone: str,
    source: str,
    max_age_seconds: int | None = None,
) -> dict[str, Any] | None:
    """Return a fresh lookup for (phone, source) or None.

    max_age_seconds: if set and the entry is older than this, treat as absent.
    """
    with _lock:
        conn = _connect(db_path)
        try:
            row = conn.execute(
                "SELECT * FROM phone_lookups WHERE phone=? AND source=?",
                (phone, source),
            ).fetchone()
            if row is None:
                return None
            entry = dict(row)
            entry["data"] = json.loads(entry["data"])
            if max_age_seconds is not None:
                fetched = datetime.fromisoformat(entry["fetched_at"])
                if datetime.now(timezone.utc) - fetched > timedelta(seconds=max_age_seconds):
                    return None
            return entry
        finally:
            conn.close()


def save_lookup(
    db_path: str,
    phone: str,
    source: str,
    data: dict[str, Any],
    status: str = "ok",
    ttl_seconds: int | None = None,
) -> None:
    """Insert or replace a phone lookup."""
    now = _now()
    expires = None
    if ttl_seconds is not None:
        expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    with _lock:
        conn = _connect(db_path)
        try:
            conn.execute(
                """
                INSERT INTO phone_lookups (phone, source, data, status, fetched_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(phone, source) DO UPDATE SET
                    data=excluded.data, status=excluded.status,
                    fetched_at=excluded.fetched_at, expires_at=excluded.expires_at
                """,
                (phone, source, json.dumps(data), status, now, expires),
            )
            conn.commit()
        finally:
            conn.close()


def query_phone(db_path: str, phone: str) -> list[dict[str, Any]]:
    """Return all sources' lookups for a phone."""
    with _lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM phone_lookups WHERE phone=? ORDER BY fetched_at DESC",
                (phone,),
            ).fetchall()
            out = []
            for r in rows:
                e = dict(r)
                e["data"] = json.loads(e["data"])
                out.append(e)
            return out
        finally:
            conn.close()


def list_phones(db_path: str, limit: int = 200) -> list[dict[str, Any]]:
    """List distinct phones with their latest fetch time."""
    with _lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                """
                SELECT phone, MAX(fetched_at) AS last_fetch, COUNT(*) AS source_count
                FROM phone_lookups GROUP BY phone ORDER BY last_fetch DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def count(db_path: str) -> int:
    """Total number of stored lookups."""
    with _lock:
        conn = _connect(db_path)
        try:
            return conn.execute("SELECT COUNT(*) AS n FROM phone_lookups").fetchone()["n"]
        finally:
            conn.close()
