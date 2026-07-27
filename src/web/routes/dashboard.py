"""Dashboard route — summary stats at /."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

HERE = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(HERE / "templates"))

router = APIRouter(tags=["dashboard"])


def _load_scan_history() -> list[dict]:
    """Load all scan result JSON files from known locations."""
    results: list[dict] = []

    search_dirs: list[Path] = [
        Path.cwd(),
        Path.home() / ".1ai-osint",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for f in sorted(search_dir.glob("*.json")):
            # Skip known non-scan files
            skip_patterns = (
                ".osint_rate_limit",
                "package-lock",
                "package",
                "tsconfig",
                "cov",
            )
            if any(p in f.name for p in skip_patterns):
                continue
            try:
                import json

                data = json.loads(f.read_text())
                # Accept files that look like scan results
                if isinstance(data, dict) and (
                    "scan_id" in data or "report_id" in data or "findings" in data or "modules_run" in data
                ):
                    results.append(data)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and ("scan_id" in item or "findings" in item):
                            results.append(item)
            except (json.JSONDecodeError, OSError):
                continue

    return results


def _compute_dashboard_stats(history: list[dict]) -> dict:
    """Derive summary statistics from scan history."""
    total_scans = len(history)
    all_findings: list[str] = []
    modules_run: Counter = Counter()
    risk_dist: Counter = Counter()

    # Track unique entity identifiers
    entities: set[str] = set()

    for scan in history:
        # Count findings
        findings = scan.get("findings", [])
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict):
                    all_findings.append(f.get("title", ""))
                    sev = f.get("severity", "info")
                    risk_dist[sev] += 1
                    target = f.get("target", "")
                    if target:
                        entities.add(target)

        # Count modules
        modules = scan.get("modules_run", [])
        if isinstance(modules, list):
            for m in modules:
                if isinstance(m, str):
                    modules_run[m] += 1

        module = scan.get("module", "")
        if module:
            modules_run[module] += 1

        # Check for evidence/entities
        evidence = scan.get("evidence", [])
        if isinstance(evidence, list):
            for e in evidence:
                if isinstance(e, dict):
                    eid = e.get("entity_id") or e.get("id") or e.get("title", "")
                    if eid:
                        entities.add(str(eid))

        # Identity tracking
        identities = scan.get("identities", [])
        if isinstance(identities, list):
            for ident in identities:
                if isinstance(ident, dict):
                    eid = ident.get("id") or ident.get("zkit_hash", "")
                    if eid:
                        entities.add(str(eid))

        # Risk block
        risk = scan.get("risk", {})
        if isinstance(risk, dict):
            level = risk.get("level", "unknown")
            risk_dist[level] += 1

    # Total entity count
    total_entities = len(entities)

    # Top modules
    top_modules = modules_run.most_common(10)

    return {
        "total_scans": total_scans,
        "total_entities": total_entities,
        "total_findings": len(all_findings),
        "modules_run": top_modules,
        "risk_distribution": dict(risk_dist),
    }


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    """Render the dashboard with summary statistics."""
    history = _load_scan_history()
    stats = _compute_dashboard_stats(history)

    return TEMPLATES.TemplateResponse(
        request,
        "dashboard.html",
        {
            "stats": stats,
            "recent_scans": history[-20:][::-1],  # most recent first
            "page_title": "Dashboard",
        },
    )
