"""FastAPI service for async deep-scan jobs."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="1ai-osint API", version="0.1.0")
_JOBS: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    profile: str = Field(default="standard", pattern="^(fast|standard|deep|agency)$")
    case_id: str = ""


class ScanResponse(BaseModel):
    job_id: str
    status: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "1ai-osint"}


@app.post("/v1/scan", response_model=ScanResponse)
async def create_scan(req: ScanRequest):
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    _JOBS[job_id] = {
        "status": "queued",
        "target": req.target,
        "profile": req.profile,
        "case_id": req.case_id,
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
    from src.modules.deep_scan.engine import DeepScanEngine
    from src.modules.deep_scan.exports import export_report
    from src.modules.deep_scan.report_generator import generate_intel_report
    from src.modules.deep_scan.scan_profiles import resolve_scan_profile
    from src.investigations.case_manager import CaseManager

    _JOBS[job_id]["status"] = "running"
    try:
        prof = resolve_scan_profile(req.profile)
        engine = DeepScanEngine(profile_config=prof, modules=list(prof.modules))
        result = await engine.scan(req.target)
        intel = generate_intel_report(result)
        html = export_report(intel, fmt="html")
        js = export_report(intel, fmt="json")
        pdf = export_report(intel, fmt="pdf")
        _JOBS[job_id].update({
            "status": "completed",
            "intel": js if isinstance(js, str) else js.decode(),
            "html": html if isinstance(html, str) else "",
        })
        if req.case_id:
            CaseManager().save_run(
                req.case_id, req.target, result, intel,
                html=html if isinstance(html, str) else "",
                json_report=js if isinstance(js, str) else "",
                pdf_bytes=pdf if isinstance(pdf, bytes) else None,
            )
    except Exception as exc:
        _JOBS[job_id]["status"] = "failed"
        _JOBS[job_id]["error"] = str(exc)
