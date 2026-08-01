"""FastAPI service for async deep-scan jobs.

Serves both the legacy ``/v1`` JSON API and the ZKIT React dashboard
(``/api``) endpoints. Both paths share a single job store (``_JOBS``) and a
single job runner (``_run_job``) so behaviour does not drift between them.

Jobs are persisted to ``<project_root>/state/jobs/jobs.json`` so a restart
does not lose in-flight results. Persistence is skipped under pytest and is
best-effort (atomic write, failures logged away) so it can never break a
request.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

load_dotenv()

from src.core.config import settings  # noqa: E402
from src.core.rate_limiter import RequestLimiter  # noqa: E402
from src.core.rbac import AccessTier  # noqa: E402
from src.core.ssrf_guard import validate_scan_target  # noqa: E402

logger = logging.getLogger(__name__)

app = FastAPI(title="1ai-osint API", version="0.1.0")
_JOBS: dict[str, dict[str, Any]] = {}
_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

#: Strong references to in-flight asyncio tasks. ``asyncio.create_task``
#: returns a task that is garbage-collected mid-execution unless the caller
#: keeps a reference, which silently cancels long scans; this set (with the
#: done-callback below) prevents that.
_TASKS: set[asyncio.Task] = set()

_MAX_PERSISTED_JOBS = 100


def _env_int(name: str, default: int) -> int:
    """Parse an env var as a positive int, falling back to ``default``."""
    raw = os.environ.get(name, "").strip()
    try:
        return max(int(raw), 1)
    except (TypeError, ValueError):
        return default


#: Inbound per-client gate for scan-creation endpoints. Deliberately separate
#: from the outbound ``RateLimiter`` (per-source token bucket): this throttles
#: who can *queue* work, the other throttles external calls. In-memory only —
#: a restart resets it, which is fine for abuse protection.
_api_limiter = RequestLimiter(
    requests_per_minute=_env_int("AI_OSINT_API_RPM", 60),
    burst=_env_int("AI_OSINT_API_BURST", 30),
)


def _rate_limit_or_429(request: Request) -> None:
    """Reject a scan-creation request when the client is over its quota."""
    client = request.client.host if request.client else "unknown"
    if not _api_limiter.allow(client):
        # Time until the bucket refills one token: 1/rate seconds, rounded up.
        retry_after = max(1, math.ceil(1.0 / _api_limiter.rate))
        plural = "s" if retry_after != 1 else ""
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Retry after {retry_after} second{plural}.",
            headers={"Retry-After": str(retry_after)},
        )


def _load_template(name: str) -> str:
    return (_TEMPLATE_DIR / name).read_text()


def _in_pytest() -> bool:
    return "pytest" in sys.modules


def _jobs_dir() -> pathlib.Path:
    env_dir = os.environ.get("AI_OSINT_JOBS_DIR")
    if env_dir:
        return pathlib.Path(env_dir)
    if settings.api_jobs_dir:
        return pathlib.Path(settings.api_jobs_dir)
    return settings.project_root / "state" / "jobs"


_JOBS_FILE = _jobs_dir() / "jobs.json"


def _load_jobs() -> dict[str, dict[str, Any]]:
    """Restore previously persisted jobs (newest first, capped)."""
    if _in_pytest():
        return {}
    try:
        if not _JOBS_FILE.exists():
            return {}
        raw = json.loads(_JOBS_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {}
        items = sorted(
            (v for v in raw.values() if isinstance(v, dict) and v.get("job_id")),
            key=lambda item: str(item.get("created_at") or ""),
            reverse=True,
        )
        # Jobs restored from a crash may have been mid-run; never resurrect
        # them as "running" (a resumed runner would double-execute).
        for item in items:
            if item.get("status") == "running":
                item["status"] = "interrupted"
        return {item["job_id"]: item for item in items[:_MAX_PERSISTED_JOBS]}
    except Exception as exc:
        logger.warning("failed to load persisted jobs from %s: %s", _JOBS_FILE, exc)
        return {}


def _save_jobs() -> None:
    """Persist the job store atomically; never raises into request handlers."""
    if _in_pytest():
        return
    try:
        _JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(_JOBS, indent=2, default=str)
        tmp = _JOBS_FILE.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, _JOBS_FILE)
    except Exception as exc:
        logger.warning("failed to persist jobs to %s: %s", _JOBS_FILE, exc)


_JOBS = _load_jobs()


def _track(task: asyncio.Task) -> asyncio.Task:
    """Keep a strong reference so a background task is never GC'd mid-run."""
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return task


def _cors_origins() -> list[str]:
    raw = os.environ.get("AI_OSINT_CORS_ORIGINS") or settings.api_cors_origins
    if raw:
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    # Local dev: the Vite dev server. Explicit origins (never "*") so we can
    # keep allow_credentials=True, which is invalid with a wildcard origin.
    return ["http://localhost:5173", "http://127.0.0.1:5173"]


class ScanRequest(BaseModel):
    target: str = Field(min_length=1)
    profile: str = Field(default="standard", pattern="^(fast|standard|deep)$")
    case_id: str = ""
    budget: float = Field(default=15.0, ge=0.0)
    max_iterations: int | None = None


class ScanResponse(BaseModel):
    job_id: str
    status: str


class ReactScanRequest(BaseModel):
    target: str = Field(min_length=1)
    fast: bool = True
    max_iterations: int = Field(default=5, ge=1)


class ReactJobResponse(BaseModel):
    job_id: str
    status: str
    target: str


def _create_job(
    job_id: str,
    *,
    target: str,
    profile: str,
    case_id: str = "",
    budget: float = 15.0,
    max_iterations: int | None = None,
) -> dict[str, Any]:
    job: dict[str, Any] = {
        "job_id": job_id,
        "status": "queued",
        "target": target,
        "profile": profile,
        "case_id": case_id,
        "budget": budget,
        "max_iterations": max_iterations,
        "retry_count": 0,
        "last_error": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "intel": None,
        "html": None,
        "error": None,
    }
    _JOBS[job_id] = job
    _save_jobs()
    return job


def _clean_target(req: ScanRequest) -> None:
    """Reject blank / internal targets and normalise the value in place."""
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="target must not be empty")
    if not validate_scan_target(target):
        raise HTTPException(status_code=422, detail="Blocked private/internal scan target")
    req.target = target


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "1ai-osint"}


@app.get("/v1/jobs")
def list_jobs() -> list[dict[str, Any]]:
    jobs = [
        {
            "job_id": job_id,
            "status": job.get("status", "unknown"),
            "target": job.get("target", "unknown"),
            "profile": job.get("profile", "unknown"),
            "budget": job.get("budget", 15.0),
            "created_at": job.get("created_at", datetime.now(timezone.utc).isoformat()),
            "error": job.get("error"),
        }
        for job_id, job in _JOBS.items()
    ]
    jobs.sort(key=lambda job: str(job["created_at"]), reverse=True)
    return jobs


@app.post("/v1/scan", response_model=ScanResponse)
async def create_scan(request: Request, req: ScanRequest) -> ScanResponse:
    _rate_limit_or_429(request)
    _clean_target(req)
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    _create_job(job_id, target=req.target, profile=req.profile, case_id=req.case_id, budget=req.budget)
    requester_tier = request.scope.get("auth_tier", AccessTier.READONLY)
    _track(asyncio.create_task(_run_job(job_id, req, requester_tier=requester_tier)))
    return ScanResponse(job_id=job_id, status="queued")


@app.get("/v1/scan/{job_id}")
def get_scan(job_id: str) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


async def _run_job(job_id: str, req: ScanRequest, requester_tier: AccessTier = AccessTier.READONLY) -> None:
    from src.investigations.case_manager import CaseManager
    from src.modules.deep_scan.engine import DeepScanEngine
    from src.modules.deep_scan.exports import export_report
    from src.modules.deep_scan.report_generator import generate_intel_report_with_ai
    from src.modules.deep_scan.scan_profiles import resolve_scan_profile

    job = _JOBS.get(job_id)
    if job is None:
        # Tolerate callers (tests, restored minimal records) that only set status.
        job = {"status": "queued", "target": req.target, "profile": req.profile}
        _JOBS[job_id] = job
    now = datetime.now(timezone.utc).isoformat()
    job.update({"status": "running", "started_at": now})
    _save_jobs()
    try:
        prof = resolve_scan_profile(req.profile)
        kwargs: dict[str, Any] = {
            "profile_config": prof,
            "modules": list(prof.modules),
            "budget": req.budget,
            "requester_tier": requester_tier,
        }
        if req.max_iterations is not None:
            kwargs["max_iterations"] = req.max_iterations
        engine = DeepScanEngine(**kwargs)
        result = await engine.scan(req.target)
        intel = generate_intel_report_with_ai(result, use_ai=True)
        html = export_report(intel, fmt="html")
        js = export_report(intel, fmt="json")
        pdf = export_report(intel, fmt="pdf")
        job.update(
            {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "result": result.to_dict(),
                "intel": js if isinstance(js, str) else js.decode(),
                "html": html if isinstance(html, str) else "",
            }
        )
        _save_jobs()
        if req.case_id:
            CaseManager().save_run(
                req.case_id,
                req.target,
                result,
                intel,
                html=html if isinstance(html, str) else "",
                json_report=js if isinstance(js, str) else "",
                pdf_bytes=pdf if isinstance(pdf, bytes) else None,
            )
    except Exception as exc:
        logger.exception("job %s failed while scanning target %r", job_id, req.target)
        job.update(
            {
                "status": "failed",
                "error": str(exc),
                "last_error": str(exc),
                "retry_count": int(job.get("retry_count", 0)) + 1,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        _save_jobs()


@app.get("/ui", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
def serve_ui() -> str:
    return _load_template("dashboard.html")


@app.post("/api/scan", response_model=ReactJobResponse)
async def start_scan_react(request: Request, req: ReactScanRequest) -> ReactJobResponse:
    _rate_limit_or_429(request)
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="target must not be empty")
    if not validate_scan_target(target):
        raise HTTPException(status_code=422, detail="Blocked private/internal scan target")
    profile = "fast" if req.fast else "standard"
    scan_req = ScanRequest(target=target, profile=profile, max_iterations=req.max_iterations)
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    _create_job(job_id, target=target, profile=profile, max_iterations=req.max_iterations)
    requester_tier = request.scope.get("auth_tier", AccessTier.READONLY)
    _track(asyncio.create_task(_run_job(job_id, scan_req, requester_tier=requester_tier)))
    return ReactJobResponse(job_id=job_id, status="queued", target=target)


@app.get("/api/scan/{job_id}")
async def get_scan_status_react(job_id: str) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# --- Optional bearer-token auth (mirrors src.web.app) ---------------------
# Fail-open default: with no tokens configured the API stays open but every
# request is treated as READONLY tier (least privilege) — see the handler
# default in ``_run_job`` and the ``request.scope.get("auth_tier", ...)``
# lookups. Set REQUIRE_AUTH_TOKENS=1 (with no tokens) to fail closed instead:
# every non-exempt request is then rejected with 401. When
# WEB_AUTH_TOKEN / WEB_AUTH_TOKENS are configured, auth is on regardless.
# The UI/health paths served here are exempt so the dashboard stays reachable.
from src.core.rbac import tiers_from_env  # noqa: E402
from src.web.app import AuthMiddleware as _BaseAuthMiddleware  # noqa: E402


class _ApiAuthMiddleware(_BaseAuthMiddleware):
    """Bearer-token gate that also exempts the API's own health/UI paths."""

    def _is_authorized(self, scope) -> bool:
        path = scope.get("path", "")
        if path in ("/health", "/ui", "/") or path.startswith("/static"):
            return True
        return super()._is_authorized(scope)


_tokens = tiers_from_env()
_require_auth = os.environ.get("REQUIRE_AUTH_TOKENS", "").strip().lower() in {"1", "true", "yes"}
if _tokens or _require_auth:
    app.add_middleware(
        _ApiAuthMiddleware,
        token=os.environ.get("WEB_AUTH_TOKEN", "").strip() or None,
        tokens=_tokens,
    )

# CORS must be added last so it ends up outermost (preflight answers before
# auth is consulted) — Starlette wraps the stack with each new middleware.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
