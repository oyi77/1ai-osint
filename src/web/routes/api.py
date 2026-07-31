"""API endpoints — health, search, and data access."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from src.core.rbac import AccessTier

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/auth/tier")
async def auth_tier(request: Request) -> dict:
    """Return the caller's resolved access tier (RBAC Layer 3).

    When auth is disabled (no WEB_AUTH_TOKEN / WEB_AUTH_TOKENS) the caller
    is treated as ADMIN — same as the engine's internal default.
    """
    tier = request.scope.get("auth_tier", AccessTier.ADMIN)
    return {"tier": tier.name, "rank": int(tier)}


@router.get("/health")
async def health_check() -> dict:
    """System health check — verifies core dependencies are available."""
    statuses: dict[str, str | bool] = {
        "status": "ok",
        "version": "1.0.0",
    }
    # Check database module availability
    db_available = importlib.util.find_spec("src.core.database") is not None
    statuses["database_available"] = db_available

    # Check AI orchestrator
    ai_available = importlib.util.find_spec("src.ai.orchestrator") is not None
    statuses["ai_available"] = ai_available

    # Check source modules
    sources_available = importlib.util.find_spec("src.modules.sources") is not None
    statuses["sources_available"] = sources_available

    # Check ZKIT engine
    zkit_available = importlib.util.find_spec("src.modules.identity_tracking.zkit_engine") is not None
    statuses["zkit_available"] = zkit_available

    # Check deep scan
    deep_scan_available = importlib.util.find_spec("src.modules.deep_scan.engine") is not None
    statuses["deep_scan_available"] = deep_scan_available

    # Check data directories
    data_dirs = [Path.cwd(), Path.home() / ".1ai-osint"]
    writable_dirs = [str(d) for d in data_dirs if d.exists() and d.is_dir()]
    statuses["data_directories"] = "; ".join(writable_dirs) if writable_dirs else "none"

    return statuses


@router.get("/stats")
async def stats_overview() -> dict:
    """Quick overview stats — scan count, finding count, entity count."""
    from src.web.routes.dashboard import _compute_dashboard_stats, _load_scan_history

    history = _load_scan_history()
    stats = _compute_dashboard_stats(history)

    return {
        "total_scans": stats.get("total_scans", 0),
        "total_findings": stats.get("total_findings", 0),
        "total_entities": stats.get("total_entities", 0),
        "modules_run": len(stats.get("modules_run", [])),
        "risk_distribution": dict(stats.get("risk_distribution", {})),
    }


@router.get("/search")
async def search_all(q: str = "") -> dict:
    """Search across entities, reports, and findings."""
    if not q or len(q.strip()) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters")

    query = q.strip().lower()

    # Search entities
    from src.web.routes.entities import _load_all_entities

    entities = _load_all_entities()
    matched_entities = [e for e in entities if query in e.get("id", "").lower() or query in e.get("source", "").lower()]

    # Search reports
    from src.web.routes.reports import _load_reports

    reports = _load_reports()
    matched_reports = [
        r
        for r in reports
        if query in r.get("target", "").lower()
        or query in r.get("scan_id", "").lower()
        or query in r.get("module", "").lower()
    ]

    return {
        "query": q,
        "entities": matched_entities[:20],
        "reports": matched_reports[:20],
        "entity_count": len(matched_entities),
        "report_count": len(matched_reports),
    }
