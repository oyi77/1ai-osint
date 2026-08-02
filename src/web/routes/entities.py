"""Entity browsing routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from src.web.routes._loader import load_scan_items

HERE = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(HERE / "templates"))

router = APIRouter(tags=["entities"])


def _load_all_entities() -> list[dict]:
    """Extract all unique entities from scan result files."""
    entities_map: dict[str, dict] = {}

    for _f, item in load_scan_items():
        target = item.get("target", "")
        if target:
            eid = str(target)
            if eid not in entities_map:
                entities_map[eid] = {
                    "id": eid,
                    "source": item.get("module", ""),
                    "finding_count": 0,
                    "risk_level": "unknown",
                    "first_seen": item.get("started_at", ""),
                    "last_seen": item.get("completed_at", ""),
                    "scan_ids": set(),
                }
            ent = entities_map[eid]
            ent["scan_ids"].add(item.get("scan_id", ""))
            finding_count = len(item.get("findings", [])) if isinstance(item.get("findings"), list) else 0
            ent["finding_count"] += finding_count
            if item.get("completed_at", "") > ent["last_seen"]:
                ent["last_seen"] = item["completed_at"]
            if item.get("started_at", "") and (not ent["first_seen"] or item["started_at"] < ent["first_seen"]):
                ent["first_seen"] = item["started_at"]
            # Risk from deep scan reports
            risk = item.get("risk", {})
            if isinstance(risk, dict):
                ent["risk_level"] = risk.get("level", ent["risk_level"])

        # Also extract entities from findings
        findings = item.get("findings", [])
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    raw = finding.get("raw_data", {}) or {}
                    for key in ("email", "username", "domain", "phone", "address", "target"):
                        val = raw.get(key) or finding.get(key)
                        if val:
                            eid = str(val)
                            if eid not in entities_map:
                                entities_map[eid] = {
                                    "id": eid,
                                    "source": finding.get("module", item.get("module", "")),
                                    "finding_count": 0,
                                    "risk_level": finding.get("severity", "info"),
                                    "first_seen": item.get("started_at", ""),
                                    "last_seen": item.get("completed_at", ""),
                                    "scan_ids": set(),
                                }
                            entities_map[eid]["finding_count"] += 1
                            entities_map[eid]["scan_ids"].add(item.get("scan_id", ""))

    # Convert sets to lists for JSON serialization
    for ent in entities_map.values():
        ent["scan_ids"] = list(ent["scan_ids"])

    return sorted(entities_map.values(), key=lambda e: e["finding_count"], reverse=True)


def _load_entity_timeline(entity_id: str) -> list[dict]:
    """Load timeline events for a specific entity from scan results."""
    events: list[dict] = []

    for _f, item in load_scan_items():
        # Check if this scan result mentions our entity
        target = item.get("target", "")
        scan_id = item.get("scan_id", "") or item.get("report_id", "")
        module = item.get("module", "")
        ts_str = item.get("started_at") or item.get("completed_at") or ""
        event_type = "scan"

        if target and entity_id.lower() in target.lower():
            events.append(
                {
                    "event_type": event_type,
                    "entity_id": entity_id,
                    "timestamp": ts_str,
                    "source": module,
                    "context": {
                        "scan_id": scan_id,
                        "target": target,
                        "finding_count": len(item.get("findings", [])) if isinstance(item.get("findings"), list) else 0,
                    },
                }
            )

        # Also check findings
        findings = item.get("findings", [])
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    raw = finding.get("raw_data", {}) or {}
                    match_keywords = [raw.get(k, "") for k in ("email", "username", "domain", "phone", "address")]
                    match_keywords.append(finding.get("title", ""))
                    if any(entity_id.lower() in str(v).lower() for v in match_keywords if v):
                        events.append(
                            {
                                "event_type": "finding",
                                "entity_id": entity_id,
                                "timestamp": finding.get("timestamp", ts_str),
                                "source": finding.get("module", module),
                                "context": {
                                    "finding_id": finding.get("id", ""),
                                    "title": finding.get("title", ""),
                                    "severity": finding.get("severity", "info"),
                                    "confidence": finding.get("confidence", 0),
                                    "scan_id": scan_id,
                                },
                            }
                        )
                        break

    # Sort by timestamp
    def _sort_key(e):
        ts = e.get("timestamp", "")
        if not ts:
            return ""
        return str(ts)

    events.sort(key=_sort_key)
    return events


@router.get("/entities", response_class=HTMLResponse, include_in_schema=False)
async def entities_list(request: Request):
    """List all entities found in scan results."""
    entities = _load_all_entities()
    return TEMPLATES.TemplateResponse(
        request,
        "entities.html",
        {"entities": entities, "page_title": "Entities"},
    )


@router.get("/entities/{entity_id:path}", response_class=HTMLResponse, include_in_schema=False)
async def entity_detail(request: Request, entity_id: str):
    """Show detail view for a specific entity with timeline events."""
    entities = _load_all_entities()
    entity = next((e for e in entities if e["id"] == entity_id), None)
    if not entity:
        entity = {"id": entity_id, "source": "unknown", "finding_count": 0, "risk_level": "unknown", "scan_ids": []}

    timeline = _load_entity_timeline(entity_id)

    # Try to integrate with EntityTimeline module if available
    import importlib

    et_available = importlib.util.find_spec("src.modules.entity_timeline") is not None

    return TEMPLATES.TemplateResponse(
        request,
        "entity_detail.html",
        {
            "entity": entity,
            "timeline": timeline,
            "et_available": et_available,
            "page_title": f"Entity: {entity_id}",
        },
    )
