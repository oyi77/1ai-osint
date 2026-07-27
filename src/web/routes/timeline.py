"""Timeline routes — global and per-entity timelines."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

HERE = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(HERE / "templates"))

router = APIRouter(tags=["timeline"])


def _load_all_events() -> list[dict]:
    """Load all timeline events from scan results."""
    import json

    events: list[dict] = []
    search_dirs = [Path.cwd(), Path.home() / ".1ai-osint"]
    skip_patterns = (".osint_rate_limit", "package-lock", "package", "tsconfig", "cov")

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for f in sorted(search_dir.glob("*.json")):
            if any(p in f.name for p in skip_patterns):
                continue
            try:
                data = json.loads(f.read_text())
                items = [data] if isinstance(data, dict) else data if isinstance(data, list) else []
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    scan_id = item.get("scan_id", "") or item.get("report_id", "")
                    target = item.get("target", "")
                    module = item.get("module", "")
                    ts = item.get("started_at", "") or item.get("completed_at", "")

                    # Scan-level event
                    if scan_id:
                        finding_count = len(item.get("findings", [])) if isinstance(item.get("findings"), list) else 0
                        events.append(
                            {
                                "event_type": "scan",
                                "entity_id": target or scan_id,
                                "timestamp": ts or "",
                                "source": module,
                                "title": f"Scan: {target or scan_id}",
                                "context": {
                                    "scan_id": scan_id,
                                    "target": target,
                                    "finding_count": finding_count,
                                    "status": item.get("status", ""),
                                },
                            }
                        )

                    # Individual findings as events
                    findings = item.get("findings", [])
                    if isinstance(findings, list):
                        for finding in findings:
                            if isinstance(finding, dict):
                                events.append(
                                    {
                                        "event_type": "finding",
                                        "entity_id": target or finding.get("id", ""),
                                        "timestamp": str(finding.get("timestamp", ts or "")),
                                        "source": finding.get("module", module),
                                        "title": finding.get("title", ""),
                                        "context": {
                                            "finding_id": finding.get("id", ""),
                                            "severity": finding.get("severity", "info"),
                                            "confidence": finding.get("confidence", 0),
                                            "scan_id": scan_id,
                                        },
                                    }
                                )
            except (json.JSONDecodeError, OSError):
                continue

    # Sort reverse chronological
    events.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return events


def _load_timeline_for_entity(entity_id: str) -> list[dict]:
    """Load all events related to a specific entity."""
    all_events = _load_all_events()
    entity_events = [
        e
        for e in all_events
        if entity_id.lower() in str(e.get("entity_id", "")).lower()
        or entity_id.lower() in str(e.get("context", {}).get("target", "")).lower()
    ]
    # Sort chronological
    entity_events.sort(key=lambda e: str(e.get("timestamp", "")))
    return entity_events


def _build_graph_data(entity_id: str) -> dict:
    """Build graph data (nodes + edges) for vis.js visualization."""
    events = _load_timeline_for_entity(entity_id)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    # Entity node
    nodes[entity_id] = {
        "id": entity_id,
        "label": entity_id,
        "group": "entity",
        "title": f"Entity: {entity_id}",
        "size": 25,
    }

    for ev in events:
        source = ev.get("source", "unknown")
        event_id = f"{ev.get('context', {}).get('scan_id', '')}-{ev.get('context', {}).get('finding_id', '')}"
        if not event_id:
            event_id = f"evt-{hash(str(ev)) % 100000}"

        label = ev.get("title", ev.get("event_type", "event"))[:30]
        group = ev.get("event_type", "event")

        nodes[event_id] = {
            "id": event_id,
            "label": label,
            "group": group,
            "title": f"{ev.get('event_type', '')}: {label} (source: {source})",
            "size": 10 + (ev.get("context", {}).get("confidence", 0) * 10),
        }

        edges.append(
            {
                "from": entity_id,
                "to": event_id,
                "label": source,
            }
        )

        # Source module node
        if source and source not in nodes:
            nodes[source] = {
                "id": source,
                "label": source,
                "group": "source",
                "title": f"Source module: {source}",
                "size": 15,
            }
        if source:
            edges.append(
                {
                    "from": event_id,
                    "to": source,
                    "label": "from",
                    "color": {"color": "rgba(100, 180, 255, 0.3)"},
                }
            )

    return {
        "nodes": [v for v in nodes.values()],
        "edges": edges,
    }


@router.get("/timeline", response_class=HTMLResponse, include_in_schema=False)
async def timeline_global(request: Request):
    """Render global timeline of all events."""
    events = _load_all_events()
    return TEMPLATES.TemplateResponse(
        request,
        "timeline.html",
        {"events": events, "page_title": "Timeline", "entity_id": None},
    )


@router.get("/timeline/{entity_id:path}", response_class=HTMLResponse, include_in_schema=False)
async def timeline_for_entity(request: Request, entity_id: str):
    """Render per-entity timeline."""
    events = _load_timeline_for_entity(entity_id)
    graph_data = _build_graph_data(entity_id)
    return TEMPLATES.TemplateResponse(
        request,
        "timeline.html",
        {
            "events": events,
            "entity_id": entity_id,
            "graph_data": graph_data,
            "page_title": f"Timeline: {entity_id}",
        },
    )


@router.get("/api/timeline/{entity_id}.json")
async def timeline_api_json(entity_id: str) -> dict:
    """JSON endpoint for graph data."""
    graph_data = _build_graph_data(entity_id)
    return graph_data
