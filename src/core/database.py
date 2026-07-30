"""Async database layer with SQLite and PostgreSQL backends.

Usage:
    db = Database()  # auto-selects backend based on config
    await db.init_schema()
    await db.save_scan(result)
    ...
    await db.close()
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.models import Finding, Identity, ScanResult

_DEFAULT_DB_PATH = Path("1ai-osint.db")


class DatabaseBackend(ABC):
    """Abstract base for database backends (SQLite, PostgreSQL, etc.)."""

    @abstractmethod
    async def init_schema(self) -> None:
        """Create tables if they don't exist."""
        ...

    @abstractmethod
    async def save_scan(self, result: ScanResult) -> None:
        """Persist a ScanResult and all associated records."""
        ...

    @abstractmethod
    async def get_scan(self, scan_id: str) -> ScanResult | None:
        """Retrieve a scan by ID, including findings."""
        ...

    @abstractmethod
    async def save_identity(self, identity: Identity) -> None:
        """Persist or update a ZKIT identity."""
        ...

    @abstractmethod
    async def get_identity(self, zkit_hash: str) -> Identity | None:
        """Retrieve an identity by ZKIT hash."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Release all resources (connections, pools)."""
        ...


# ── SQLite backend ──────────────────────────────────────────────────


class SQLiteBackend(DatabaseBackend):
    """Async SQLite backend using aiosqlite."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._conn: Any = None  # aiosqlite.Connection

    async def _connect(self) -> Any:
        """Lazy-init aiosqlite connection."""
        if self._conn is None:
            import aiosqlite

            self._conn = await aiosqlite.connect(str(self.db_path))
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    async def init_schema(self) -> None:
        conn = await self._connect()
        await conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'ok',
                metadata TEXT DEFAULT '{}',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                module TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT DEFAULT 'info',
                raw_data TEXT DEFAULT '{}',
                timestamp TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                tags TEXT DEFAULT '[]',
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS breach_records (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                source TEXT NOT NULL,
                email TEXT,
                username TEXT,
                password_hash TEXT,
                domain TEXT,
                ip_address TEXT,
                phone TEXT,
                breach_date TEXT,
                description TEXT DEFAULT '',
                data_classes TEXT DEFAULT '[]',
                severity TEXT DEFAULT 'medium',
                raw TEXT DEFAULT '{}',
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS identities (
                zkit_hash TEXT PRIMARY KEY,
                attributes TEXT DEFAULT '{}',
                correlation_id TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                sources TEXT DEFAULT '[]',
                confidence REAL DEFAULT 1.0
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_breach_scan ON breach_records(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
        await conn.commit()

    async def save_scan(self, result: ScanResult) -> None:
        conn = await self._connect()
        await conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, module, target, status, metadata, started_at, completed_at, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.scan_id,
                result.module,
                result.target,
                result.status,
                json.dumps(result.metadata),
                result.started_at.isoformat(),
                result.completed_at.isoformat() if result.completed_at else None,
                result.error,
            ),
        )
        for f in result.findings:
            await conn.execute(
                "INSERT OR REPLACE INTO findings (id, scan_id, module, title, description, severity, raw_data, timestamp, confidence, tags) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f.id,
                    result.scan_id,
                    f.module,
                    f.title,
                    f.description,
                    f.severity.value,
                    json.dumps(f.raw_data),
                    f.timestamp.isoformat(),
                    f.confidence,
                    json.dumps(f.tags),
                ),
            )
        for b in result.breach_records:
            await conn.execute(
                "INSERT INTO breach_records (scan_id, source, email, username, password_hash, domain, ip_address, phone, breach_date, description, data_classes, severity, raw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.scan_id,
                    b.source,
                    b.email,
                    b.username,
                    b.password_hash,
                    b.domain,
                    b.ip_address,
                    b.phone,
                    b.breach_date.isoformat() if b.breach_date else None,
                    b.description,
                    json.dumps(b.data_classes),
                    b.severity.value,
                    json.dumps(b.raw),
                ),
            )
        await conn.commit()

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        conn = await self._connect()
        cursor = await conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        if not row:
            return None

        findings_cursor = await conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        findings_rows = await findings_cursor.fetchall()
        findings = [
            Finding(
                id=r["id"],
                module=r["module"],
                title=r["title"],
                description=r["description"],
                severity=r["severity"],
                raw_data=json.loads(r["raw_data"]),
                timestamp=datetime.fromisoformat(r["timestamp"]),
                confidence=r["confidence"],
                tags=json.loads(r["tags"]),
            )
            for r in findings_rows
        ]

        return ScanResult(
            scan_id=row["scan_id"],
            module=row["module"],
            target=row["target"],
            status=row["status"],
            findings=findings,
            metadata=json.loads(row["metadata"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            error=row["error"],
        )

    async def save_identity(self, identity: Identity) -> None:
        conn = await self._connect()
        await conn.execute(
            "INSERT OR REPLACE INTO identities (zkit_hash, attributes, correlation_id, first_seen, last_seen, sources, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                identity.zkit_hash,
                json.dumps(identity.attributes),
                identity.correlation_id,
                identity.first_seen.isoformat(),
                identity.last_seen.isoformat(),
                json.dumps(identity.sources),
                identity.confidence,
            ),
        )
        await conn.commit()

    async def get_identity(self, zkit_hash: str) -> Identity | None:
        conn = await self._connect()
        cursor = await conn.execute("SELECT * FROM identities WHERE zkit_hash = ?", (zkit_hash,))
        row = await cursor.fetchone()
        if not row:
            return None
        return Identity(
            zkit_hash=row["zkit_hash"],
            attributes=json.loads(row["attributes"]),
            correlation_id=row["correlation_id"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            sources=json.loads(row["sources"]),
            confidence=row["confidence"],
        )

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None


# ── PostgreSQL backend ──────────────────────────────────────────────


class PostgresBackend(DatabaseBackend):
    """Async PostgreSQL backend using asyncpg."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "osint",
        user: str = "osint",
        password: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self._pool: Any = None  # asyncpg.Pool

    async def _get_pool(self) -> Any:
        """Lazy-init asyncpg connection pool."""
        if self._pool is None:
            import asyncpg

            self._pool = await asyncpg.create_pool(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                min_size=1,
                max_size=10,
            )
        return self._pool

    async def init_schema(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    module TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'ok',
                    metadata TEXT DEFAULT '{}',
                    started_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    module TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    severity TEXT DEFAULT 'info',
                    raw_data TEXT DEFAULT '{}',
                    timestamp TIMESTAMPTZ NOT NULL,
                    confidence REAL DEFAULT 0.5,
                    tags TEXT DEFAULT '[]',
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS breach_records (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    email TEXT,
                    username TEXT,
                    password_hash TEXT,
                    domain TEXT,
                    ip_address TEXT,
                    phone TEXT,
                    breach_date TIMESTAMPTZ,
                    description TEXT DEFAULT '',
                    data_classes TEXT DEFAULT '[]',
                    severity TEXT DEFAULT 'medium',
                    raw TEXT DEFAULT '{}',
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS identities (
                    zkit_hash TEXT PRIMARY KEY,
                    attributes TEXT DEFAULT '{}',
                    correlation_id TEXT,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ NOT NULL,
                    sources TEXT DEFAULT '[]',
                    confidence REAL DEFAULT 1.0
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_breach_scan ON breach_records(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            """)

    async def save_scan(self, result: ScanResult) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO scans (scan_id, module, target, status, metadata, started_at, completed_at, error) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
                    "ON CONFLICT (scan_id) DO UPDATE SET "
                    "module=EXCLUDED.module, target=EXCLUDED.target, status=EXCLUDED.status, "
                    "metadata=EXCLUDED.metadata, started_at=EXCLUDED.started_at, "
                    "completed_at=EXCLUDED.completed_at, error=EXCLUDED.error",
                    result.scan_id,
                    result.module,
                    result.target,
                    result.status,
                    json.dumps(result.metadata),
                    result.started_at,
                    result.completed_at,
                    result.error,
                )
                for f in result.findings:
                    await conn.execute(
                        "INSERT INTO findings (id, scan_id, module, title, description, severity, raw_data, timestamp, confidence, tags) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "
                        "ON CONFLICT (id) DO UPDATE SET "
                        "scan_id=EXCLUDED.scan_id, module=EXCLUDED.module, title=EXCLUDED.title, "
                        "description=EXCLUDED.description, severity=EXCLUDED.severity, "
                        "raw_data=EXCLUDED.raw_data, timestamp=EXCLUDED.timestamp, "
                        "confidence=EXCLUDED.confidence, tags=EXCLUDED.tags",
                        f.id,
                        result.scan_id,
                        f.module,
                        f.title,
                        f.description,
                        f.severity.value,
                        json.dumps(f.raw_data),
                        f.timestamp,
                        f.confidence,
                        json.dumps(f.tags),
                    )
                for b in result.breach_records:
                    await conn.execute(
                        "INSERT INTO breach_records (scan_id, source, email, username, password_hash, domain, ip_address, phone, breach_date, description, data_classes, severity, raw) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                        result.scan_id,
                        b.source,
                        b.email,
                        b.username,
                        b.password_hash,
                        b.domain,
                        b.ip_address,
                        b.phone,
                        b.breach_date,
                        b.description,
                        json.dumps(b.data_classes),
                        b.severity.value,
                        json.dumps(b.raw),
                    )

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM scans WHERE scan_id = $1", scan_id)
            if not row:
                return None

            findings_rows = await conn.fetch("SELECT * FROM findings WHERE scan_id = $1", scan_id)
            findings = [
                Finding(
                    id=r["id"],
                    module=r["module"],
                    title=r["title"],
                    description=r["description"],
                    severity=r["severity"],
                    raw_data=json.loads(r["raw_data"]),
                    timestamp=r["timestamp"],
                    confidence=r["confidence"],
                    tags=json.loads(r["tags"]),
                )
                for r in findings_rows
            ]

            return ScanResult(
                scan_id=row["scan_id"],
                module=row["module"],
                target=row["target"],
                status=row["status"],
                findings=findings,
                metadata=json.loads(row["metadata"]),
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                error=row["error"],
            )

    async def save_identity(self, identity: Identity) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO identities (zkit_hash, attributes, correlation_id, first_seen, last_seen, sources, confidence) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7) "
                "ON CONFLICT (zkit_hash) DO UPDATE SET "
                "attributes=EXCLUDED.attributes, correlation_id=EXCLUDED.correlation_id, "
                "first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen, "
                "sources=EXCLUDED.sources, confidence=EXCLUDED.confidence",
                identity.zkit_hash,
                json.dumps(identity.attributes),
                identity.correlation_id,
                identity.first_seen,
                identity.last_seen,
                json.dumps(identity.sources),
                identity.confidence,
            )

    async def get_identity(self, zkit_hash: str) -> Identity | None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM identities WHERE zkit_hash = $1", zkit_hash)
            if not row:
                return None
            return Identity(
                zkit_hash=row["zkit_hash"],
                attributes=json.loads(row["attributes"]),
                correlation_id=row["correlation_id"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                sources=json.loads(row["sources"]),
                confidence=row["confidence"],
            )

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None


# ── Thin facade ─────────────────────────────────────────────────────


class Database:
    """Thin async facade over DatabaseBackend.

    Auto-selects SQLite or PostgreSQL backend based on config.
    Calls are delegated to the underlying backend.
    """

    def __init__(self, backend: DatabaseBackend | None = None) -> None:
        self._backend = backend or self._create_backend()

    @staticmethod
    def _create_backend() -> DatabaseBackend:
        from src.core.config import settings

        if settings.db_type == "postgres":
            return PostgresBackend(
                host=settings.db_host,
                port=settings.db_port,
                database=settings.db_name,
                user=settings.db_user,
                password=settings.db_password,
            )
        return SQLiteBackend(db_path=settings.db_path)

    async def init_schema(self) -> None:
        await self._backend.init_schema()

    async def save_scan(self, result: ScanResult) -> None:
        await self._backend.save_scan(result)

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        return await self._backend.get_scan(scan_id)

    async def save_identity(self, identity: Identity) -> None:
        await self._backend.save_identity(identity)

    async def get_identity(self, zkit_hash: str) -> Identity | None:
        return await self._backend.get_identity(zkit_hash)

    async def close(self) -> None:
        await self._backend.close()
