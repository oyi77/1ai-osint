"""Export ZKIT identity graph as Neo4j-compatible JSON."""

from __future__ import annotations

from typing import Any


def export_neo4j_json(graph: Any) -> dict:
    """Convert IdentityGraph to nodes/relationships for Neo4j import."""
    nodes = []
    for n in getattr(graph, "nodes", []) or []:
        nodes.append(
            {
                "id": n.id,
                "labels": [n.type.upper() if n.type else "ENTITY"],
                "properties": {
                    "label": n.label,
                    "weight": n.weight,
                },
            }
        )
    rels = []
    for e in getattr(graph, "edges", []) or []:
        rels.append(
            {
                "type": (e.relationship or "RELATED_TO").upper(),
                "start": e.source_id,
                "end": e.target_id,
                "properties": {"weight": e.weight},
            }
        )
    return {"nodes": nodes, "relationships": rels}
