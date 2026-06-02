"""JSON export — schema-versioned serialization of IntelReport.

Outputs a deterministic JSON structure with embedded schema version
for forward compatibility.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from src.modules.deep_scan.models_report import IntelReport

SCHEMA_VERSION = "1.0.0"


def export_json(report: IntelReport, indent: int = 2) -> str:
    """Serialize an IntelReport to schema-versioned JSON."""
    return json.dumps(_to_dict(report), indent=indent, default=_json_default)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _to_dict(report: IntelReport) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_id": report.report_id,
        "target": report.target,
        "started_at": report.started_at.isoformat() if report.started_at else None,
        "completed_at": report.completed_at.isoformat() if report.completed_at else None,
        "duration_sec": report.duration_sec,
        "iterations": report.iterations,
        "modules_run": report.modules_run,
        "summary": report.summary,
        "warnings": report.warnings,
        "risk": {
            "level": report.risk.level.value,
            "score": report.risk.score,
            "reasoning": report.risk.reasoning,
            "factors": [
                {
                    "rule": f.rule,
                    "description": f.description,
                    "weight": f.weight,
                    "triggered": f.triggered,
                }
                for f in report.risk.factors
            ],
        },
        "confidence_by_identifier": {
            k: {
                "existence": v.existence,
                "uniqueness": v.uniqueness,
                "cross_module": v.cross_module,
                "temporal": v.temporal,
                "total": v.total,
                "grade": v.grade,
            }
            for k, v in report.confidence_by_identifier.items()
        },
        "evidence": [
            {
                "id": e.id,
                "identifier_value": e.identifier_value,
                "identifier_type": e.identifier_type,
                "source": e.source,
                "source_reliability": e.source_reliability,
                "url": e.url,
                "http_status": e.http_status,
                "snippet": e.snippet,
                "confidence": e.confidence,
                "notes": e.notes,
                "captured_at": e.captured_at.isoformat() if e.captured_at else None,
            }
            for e in report.evidence
        ],
        "timeline": [
            {
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                "source": t.source,
                "event": t.event,
                "detail": t.detail,
                "confidence": t.confidence,
            }
            for t in report.timeline
        ],
        "identity_graph": {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "weight": n.weight,
                }
                for n in report.identity_graph.nodes
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "relationship": e.relationship,
                    "weight": e.weight,
                    "evidence_ids": e.evidence_ids,
                }
                for e in report.identity_graph.edges
            ],
        },
        "pivots": [
            {
                "target_type": p.target_type,
                "target_value": p.target_value,
                "rationale": p.rationale,
                "priority": p.priority,
                "expected_sources": p.expected_sources,
            }
            for p in report.pivots
        ],
        "correlation": {
            "clusters": [
                {
                    "entity_id": c.get("entity_id", ""),
                    "confidence": c.get("confidence", 0),
                    "attribute_types": c.get("attribute_types", {}),
                    "source_modules": c.get("source_modules", []),
                    "evidence": c.get("correlation_evidence", []),
                }
                for c in (report.correlation_clusters or [])
            ],
            "stats": report.correlation_stats,
        },
        "breaches": [
            {
                "name": ev.raw_data.get("Name") or ev.identifier_value,
                "date": ev.raw_data.get("BreachDate") or ev.raw_data.get("breach_date"),
                "data_classes": ev.raw_data.get("DataClasses", []),
                "source": ev.source,
                "confidence": ev.confidence,
            }
            for ev in report.evidence if ev.identifier_type == "breach"
        ],
    }
