"""Report viewer routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from src.web.routes._loader import TTLCache, load_scan_items, scan_dirs_key

HERE = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(HERE / "templates"))

router = APIRouter(tags=["reports"])

_reports_cache = TTLCache()


def _load_reports() -> list[dict]:
    """Load all report-like JSON files (memoized for a short TTL)."""
    key = scan_dirs_key()
    cached = _reports_cache.get(key)
    if cached is not None:
        return cached

    reports: list[dict] = []
    for f, item in reversed(load_scan_items()):  # newest file first, as before
        # Must look like a scan report
        has_scan_id = bool(item.get("scan_id") or item.get("report_id"))
        has_findings = "findings" in item
        has_summary = "summary" in item or "modules_run" in item
        if has_scan_id or has_findings or has_summary:
            # Compute summary if missing
            findings_list = item.get("findings", [])
            if isinstance(findings_list, list):
                severity_counts: dict[str, int] = {}
                for finding in findings_list:
                    if isinstance(finding, dict):
                        sev = finding.get("severity", "info")
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
            else:
                severity_counts = {}

            reports.append(
                {
                    "file": str(f.relative_to(Path.cwd()) if f.is_relative_to(Path.cwd()) else f),
                    "filename": f.name,
                    "scan_id": item.get("scan_id") or item.get("report_id", ""),
                    "target": item.get("target", ""),
                    "module": item.get("module", ""),
                    "modules_run": item.get("modules_run", []),
                    "status": item.get("status", "ok"),
                    "started_at": item.get("started_at", ""),
                    "completed_at": item.get("completed_at", ""),
                    "duration_sec": item.get("duration_sec", None),
                    "finding_count": len(findings_list) if isinstance(findings_list, list) else 0,
                    "severity_counts": severity_counts,
                    "risk": item.get("risk", {}),
                    "summary": item.get("summary", ""),
                    "full_data": item,
                }
            )
    _reports_cache.set(key, reports)
    return reports


@router.get("/reports", response_class=HTMLResponse, include_in_schema=False)
async def reports_list(request: Request):
    """List all reports."""
    reports = _load_reports()
    return TEMPLATES.TemplateResponse(
        request,
        "reports.html",
        {"reports": reports, "page_title": "Reports"},
    )


@router.get("/reports/{report_id:path}", response_class=HTMLResponse, include_in_schema=False)
async def report_detail(request: Request, report_id: str):
    """Show full report view with evidence."""
    all_reports = _load_reports()

    # Try matching by scan_id/report_id or by filename
    report = None
    for r in all_reports:
        if r["scan_id"] == report_id or r["filename"] == report_id or r["file"] == report_id:
            report = r
            break

    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")

    return TEMPLATES.TemplateResponse(
        request,
        "report_detail.html",
        {
            "report": report,
            "findings": report.get("full_data", {}).get("findings", []),
            "page_title": f"Report: {report['scan_id'] or report['filename']}",
        },
    )
