"""Neo4j JSON serialisation helpers — graph-to-JSON conversion.

Extracted from neo4j_export.py to reduce file size.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment defaults
# ---------------------------------------------------------------------------

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")


# ---------------------------------------------------------------------------
# JSON serialisation helpers (compatible with both graph types)
# ---------------------------------------------------------------------------


def collect_nodes(graph: Any) -> list[dict[str, Any]]:
    """Collect nodes from either graph representation."""
    nodes: list[dict[str, Any]] = []

    # Try the new API first (IdentityGraph from identity_graph.py)
    if hasattr(graph, "get_all_nodes"):
        for n in graph.get_all_nodes():
            nodes.append(
                {
                    "id": n.node_id,
                    "labels": [n.node_type.value.upper() if hasattr(n.node_type, "value") else n.node_type.upper()],
                    "properties": {
                        "node_type": n.node_type.value if hasattr(n.node_type, "value") else str(n.node_type),
                        "first_seen": n.first_seen.isoformat()
                        if hasattr(n.first_seen, "isoformat")
                        else str(n.first_seen),
                        "last_seen": n.last_seen.isoformat() if hasattr(n.last_seen, "isoformat") else str(n.last_seen),
                        "sources": n.sources,
                        **n.metadata,
                    },
                }
            )
        return nodes

    # Fall back to the old API (IdentityGraph from models_report.py)
    for n in getattr(graph, "nodes", []) or []:
        node_id = getattr(n, "id", getattr(n, "node_id", ""))
        node_type = getattr(n, "type", getattr(n, "node_type", "ENTITY"))
        node_label = getattr(n, "label", "")
        weight = getattr(n, "weight", 0.0)
        metadata = getattr(n, "metadata", {}) or {}
        nodes.append(
            {
                "id": node_id,
                "labels": [str(node_type).upper()] if node_type else ["ENTITY"],
                "properties": {
                    "label": node_label,
                    "weight": weight,
                    **metadata,
                },
            }
        )
    return nodes


def collect_edges(graph: Any) -> list[dict[str, Any]]:
    """Collect edges from either graph representation."""
    edges: list[dict[str, Any]] = []

    # Try the new API first
    if hasattr(graph, "get_all_edges"):
        for e in graph.get_all_edges():
            rel_type = "RELATED_TO"
            weight = e.weight
            properties: dict[str, Any] = {"weight": weight}
            if hasattr(e, "co_occurrences"):
                properties["co_occurrences"] = e.co_occurrences
            if hasattr(e, "first_seen") and hasattr(e.first_seen, "isoformat"):
                properties["first_seen"] = e.first_seen.isoformat()
            if hasattr(e, "last_seen") and hasattr(e.last_seen, "isoformat"):
                properties["last_seen"] = e.last_seen.isoformat()
            if hasattr(e, "sources"):
                properties["sources"] = e.sources
            if hasattr(e, "metadata") and e.metadata:
                properties.update(e.metadata)
            edges.append(
                {
                    "type": rel_type,
                    "start": e.source_id,
                    "end": e.target_id,
                    "properties": properties,
                }
            )
        return edges

    # Fall back to the old API
    for e in getattr(graph, "edges", []) or []:
        rel = getattr(e, "relationship", "RELATED_TO")
        source_id = getattr(e, "source_id", getattr(e, "start", ""))
        target_id = getattr(e, "target_id", getattr(e, "end", ""))
        weight = getattr(e, "weight", 1.0)
        edges.append(
            {
                "type": str(rel).upper(),
                "start": source_id,
                "end": target_id,
                "properties": {"weight": weight},
            }
        )
    return edges


# ---------------------------------------------------------------------------
# File-based export / import
# ---------------------------------------------------------------------------


def export_neo4j_json(graph: Any) -> dict[str, Any]:
    """Convert any IdentityGraph to a Neo4j-compatible JSON dict.

    Accepts both the old ``deep_scan.models_report.IdentityGraph`` (with
    ``.nodes`` / ``.edges`` lists) and the new
    ``identity_tracking.identity_graph.IdentityGraph`` (with
    ``.get_all_nodes()`` / ``.get_all_edges()``).

    Args:
        graph: An IdentityGraph instance from either models_report or
            identity_graph.

    Returns:
        A dict with ``nodes`` and ``relationships`` keys suitable for
        Neo4j ``apoc.import.json`` or the ``bolt`` import API.
    """
    return {
        "nodes": collect_nodes(graph),
        "relationships": collect_edges(graph),
    }


def load_neo4j_json(graph: Any, filepath: str | Path) -> int:
    """Load nodes and relationships from a JSON file into an IdentityGraph.

    The JSON file should contain ``nodes`` and ``relationships`` keys
    as produced by :func:`export_neo4j_json`.

    Args:
        graph: A mutable IdentityGraph instance (must have ``add_node``
            and ``add_edge`` methods, or ``nodes.append`` / ``edges.append``).
        filepath: Path to the JSON file on disk.

    Returns:
        Number of entities (nodes + relationships) loaded.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON structure is invalid.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Neo4j JSON file not found: {filepath}")

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "nodes" not in data:
        raise ValueError("Invalid Neo4j JSON: missing 'nodes' key")

    nodes = data.get("nodes", [])
    rels = data.get("relationships", [])
    count = 0

    # Try the new API first
    if hasattr(graph, "add_node"):
        for n in nodes:
            node_id = n.get("id", "")
            labels = n.get("labels", ["ENTITY"])
            props = n.get("properties", {})
            # Derive NodeType from the label or properties
            from src.modules.identity_tracking._graph_models import NodeType

            raw_type = (props.get("node_type", labels[0] if labels else "ENTITY")).lower()
            try:
                node_type = NodeType(raw_type)
            except ValueError:
                node_type = NodeType.USERNAME_HASH  # safe default
            graph.add_node(
                node_id=node_id,
                node_type=node_type,
                source=props.get("sources", [None])[0]
                if isinstance(props.get("sources"), list) and props["sources"]
                else None,
                metadata={
                    k: v for k, v in props.items() if k not in ("node_type", "first_seen", "last_seen", "sources")
                },
            )
            count += 1

        for r in rels:
            props = r.get("properties", {})
            try:
                graph.add_edge(
                    source_id=r["start"],
                    target_id=r["end"],
                    weight=props.get("weight", 1.0),
                    source=props.get("sources", [None])[0]
                    if isinstance(props.get("sources"), list) and props["sources"]
                    else None,
                    metadata={
                        k: v
                        for k, v in props.items()
                        if k not in ("weight", "sources", "first_seen", "last_seen", "co_occurrences")
                    },
                )
                count += 1
            except (KeyError, ValueError) as e:
                logger.warning("Skipping edge %s -> %s: %s", r.get("start"), r.get("end"), e)

    # Fall back to the old API
    else:
        from src.modules.deep_scan.models_report import IdentityEdge, IdentityNode

        nodes_list: list[Any] = getattr(graph, "nodes", [])
        edges_list: list[Any] = getattr(graph, "edges", [])

        for n in nodes:
            props = n.get("properties", {})
            nodes_list.append(
                IdentityNode(
                    id=n.get("id", ""),
                    label=str(props.get("label", "")),
                    type=n.get("labels", ["ENTITY"])[0].lower(),
                    weight=float(props.get("weight", 0.0)),
                    metadata={k: v for k, v in props.items() if k not in ("label", "weight")},
                )
            )
            count += 1

        for r in rels:
            props = r.get("properties", {})
            edges_list.append(
                IdentityEdge(
                    source_id=r.get("start", ""),
                    target_id=r.get("end", ""),
                    relationship=r.get("type", "RELATED_TO").lower(),
                    weight=float(props.get("weight", 1.0)),
                )
            )
            count += 1

    return count
