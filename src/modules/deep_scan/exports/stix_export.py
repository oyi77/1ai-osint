"""STIX 2.1 export — transform IntelReport to STIX 2.1 Bundle.

Produces a valid STIX 2.1 JSON bundle with:
  - Identity SDOs for each node in identity_graph
  - URL SDOs for each evidence URL
  - Relationship SDOs for each edge
  - Confidence level translated via confidence gate (low → 0, medium → 50, high → 85)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from src.modules.deep_scan.models_report import IntelReport


STIX_VERSION = "2.1"


def _confidence_to_stix(conf: float) -> int:
    """Map confidence score to STIX confidence (0-100)."""
    if conf >= 0.8:
        return 85
    if conf >= 0.5:
        return 50
    if conf > 0:
        return 15
    return 0


def export_stix(report: IntelReport, indent: int = 2) -> str:
    """Convert an IntelReport to a STIX 2.1 Bundle JSON string."""
    objects: list[dict] = []
    now = (report.completed_at or datetime.now(timezone.utc)).isoformat()

    # Identity SDOs from identity_graph nodes
    for node in report.identity_graph.nodes:
        objects.append(
            {
                "type": "identity",
                "spec_version": STIX_VERSION,
                "id": f"identity--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": node.label,
                "identity_class": "individual",
                "confidence": _confidence_to_stix(node.weight),
                "labels": [node.type],
            }
        )

    # URL SDOs from evidence
    for ev in report.evidence:
        if not ev.url:
            continue
        objects.append(
            {
                "type": "url",
                "spec_version": STIX_VERSION,
                "id": f"url--{uuid.uuid4()}",
                "value": ev.url,
            }
        )

    # Relationship SDOs from identity_graph edges
    for edge in report.identity_graph.edges:
        objects.append(
            {
                "type": "relationship",
                "spec_version": STIX_VERSION,
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": edge.relationship,
                "source_ref": edge.source_id,
                "target_ref": edge.target_id,
                "confidence": _confidence_to_stix(edge.weight),
            }
        )

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": STIX_VERSION,
        "objects": objects,
    }

    return json.dumps(bundle, indent=indent)
