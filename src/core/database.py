"""SQLite storage for scan results, findings, and identities."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.core.models import Finding, Identity, ScanResult

_DEFAULT_DB_PATH = Path("1ai-osint.db")


class Database:
    """Thin SQLite wrapper for persisting OSINT data."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or _DEFAULT_DB_PATH
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_schema(self) -> None:
        """Create tables if they don't exist."""
        conn = self._connect()
        conn.executescript("""
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
        conn.commit()

    def save_scan(self, result: ScanResult) -> None:
        """Persist a ScanResult and all associated records."""
        conn = self._connect()
        conn.execute(
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
            conn.execute(
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
            conn.execute(
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
        conn.commit()

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve a scan by ID."""
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None

        findings_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
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
            completed_at=datetime.fromisoformat(row["completed_at"])
            if row["completed_at"]
            else None,
            error=row["error"],
        )

    def save_identity(self, identity: Identity) -> None:
        """Persist or update a ZKIT identity."""
        conn = self._connect()
        conn.execute(
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
        conn.commit()

    def get_identity(self, zkit_hash: str) -> Optional[Identity]:
        """Retrieve an identity by ZKIT hash."""
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM identities WHERE zkit_hash = ?", (zkit_hash,)
        ).fetchone()
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
