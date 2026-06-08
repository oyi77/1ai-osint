"""FastAPI service for async deep-scan jobs."""

from __future__ import annotations

import asyncio
import pathlib
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(title="1ai-osint API", version="0.1.0")
_JOBS: dict[str, dict[str, Any]] = {}
_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"


def _load_template(name: str) -> str:
    return (_TEMPLATE_DIR / name).read_text()


class ScanRequest(BaseModel):
    target: str
    profile: str = Field(default="standard", pattern="^(fast|standard|deep)$")
    case_id: str = ""
    budget: float = Field(default=15.0, ge=0.0)


class ScanResponse(BaseModel):
    job_id: str
    status: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "1ai-osint"}


@app.get("/v1/jobs")
def list_jobs():
    return [
        {
            "job_id": job_id,
            "status": job["status"],
            "target": job.get("target", "unknown"),
            "profile": job.get("profile", "unknown"),
            "budget": job.get("budget", 15.0),
            "created_at": job.get("created_at", datetime.now(timezone.utc).isoformat()),
            "error": job.get("error"),
        }
        for job_id, job in _JOBS.items()
    ]


@app.post("/v1/scan", response_model=ScanResponse)
async def create_scan(req: ScanRequest):
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    _JOBS[job_id] = {
        "status": "queued",
        "target": req.target,
        "profile": req.profile,
        "case_id": req.case_id,
        "budget": req.budget,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    asyncio.create_task(_run_job(job_id, req))
    return ScanResponse(job_id=job_id, status="queued")


@app.get("/v1/scan/{job_id}")
def get_scan(job_id: str):
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return job


async def _run_job(job_id: str, req: ScanRequest) -> None:
    from src.investigations.case_manager import CaseManager
    from src.modules.deep_scan.engine import DeepScanEngine
    from src.modules.deep_scan.exports import export_report
    from src.modules.deep_scan.report_generator import generate_intel_report_with_ai
    from src.modules.deep_scan.scan_profiles import resolve_scan_profile

    _JOBS[job_id]["status"] = "running"
    try:
        prof = resolve_scan_profile(req.profile)
        engine = DeepScanEngine(
            profile_config=prof, modules=list(prof.modules), budget=req.budget
        )
        result = await engine.scan(req.target)
        intel = generate_intel_report_with_ai(result, use_ai=True)
        html = export_report(intel, fmt="html")
        js = export_report(intel, fmt="json")
        pdf = export_report(intel, fmt="pdf")
        _JOBS[job_id].update(
            {
                "status": "completed",
                "intel": js if isinstance(js, str) else js.decode(),
                "html": html if isinstance(html, str) else "",
            }
        )
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
        _JOBS[job_id]["status"] = "failed"
        _JOBS[job_id]["error"] = str(exc)


@app.get("/ui", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return _load_template("dashboard.html")


# --- ZKIT React Dashboard Endpoints (Migrated from src/api.py) ---
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReactScanRequest(BaseModel):
    target: str
    fast: bool = True
    max_iterations: int = 5


class ReactJobResponse(BaseModel):
    job_id: str
    status: str
    target: str


async def _run_deep_scan_job_react(
    job_id: str, target: str, fast: bool, max_iterations: int
):
    from src.modules.deep_scan.engine import DeepScanEngine

    _JOBS[job_id]["status"] = "running"
    try:
        engine = DeepScanEngine(max_iterations=max_iterations, fast=fast)
        result = await engine.scan(target)
        _JOBS[job_id]["status"] = "completed"
        _JOBS[job_id]["result"] = result.to_dict()
    except Exception as e:
        _JOBS[job_id]["status"] = "failed"
        _JOBS[job_id]["error"] = str(e)


@app.post("/api/scan", response_model=ReactJobResponse)
async def start_scan_react(
    request: ReactScanRequest, background_tasks: __import__("fastapi").BackgroundTasks
):
    job_id = str(uuid.uuid4())
    _JOBS[job_id] = {
        "job_id": job_id,
        "target": request.target,
        "status": "pending",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }
    background_tasks.add_task(
        _run_deep_scan_job_react,
        job_id,
        request.target,
        request.fast,
        request.max_iterations,
    )
    return ReactJobResponse(job_id=job_id, status="pending", target=request.target)


@app.get("/api/scan/{job_id}")
async def get_scan_status_react(job_id: str):
    if job_id not in _JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
    return _JOBS[job_id]
