"""Identity Graph data structure for ZKIT identity tracking.

Graph-based representation of identity correlations using hashed attribute
nodes and co-occurrence edges. All node identifiers are salted SHA-256 hashes
— no raw PII is ever stored in the graph.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Optional

from src.modules.identity_tracking._graph_models import (
    GraphEdge,
    GraphNode,
    NodeType,
)

# Re-export models so importers can still import from identity_graph
__all__ = [
    "GraphEdge",
    "GraphNode",
    "IdentityGraph",
    "NodeType",
]


class IdentityGraph:
    """
    Graph data structure for ZKIT identity tracking.

    Nodes are hashed identity attributes (email, username, phone, domain).
    Edges represent co-occurrence — two hashes observed together during
    the same investigation or scan.

    All operations are in-memory. Persistence is handled by callers.
    """

    def __init__(self, salt: str = "") -> None:
        """
        Args:
            salt: Per-investigation salt for ZKIT hashing. If empty,
                  hashes will not be reproducible across sessions.
        """
        self._salt = salt
        self._nodes: dict[str, GraphNode] = {}
        # Adjacency: node_id -> set of neighbor node_ids
        self._adjacency: dict[str, set[str]] = defaultdict(set)
        # Edge storage: (min_id, max_id) -> GraphEdge (undirected)
        self._edges: dict[tuple[str, str], GraphEdge] = {}

    # ------------------------------------------------------------------
    # Hashing helpers
    # ------------------------------------------------------------------

    def hash_attribute(self, raw_value: str) -> str:
        """Compute ZKIT salted SHA-256 hash for a raw attribute value.

        Args:
            raw_value: The plaintext attribute (email, phone, etc.)
        Returns:
            Hex-encoded SHA-256 hash string.
        """
        preimage = f"{self._salt}:{raw_value}".encode("utf-8")
        return hashlib.sha256(preimage).hexdigest()

    # ------------------------------------------------------------------
    # Core graph operations
    # ------------------------------------------------------------------

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        source: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> GraphNode:
        """Add a node to the graph or update an existing one.

        Args:
            node_id: The ZKIT hashed identifier (SHA-256 hex).
            node_type: The type of hashed attribute.
            source: Optional source module or dataset name.
            metadata: Optional metadata dict to merge.
        Returns:
            The created or updated GraphNode.
        """
        if node_id in self._nodes:
            node = self._nodes[node_id]
            node.touch(source)
            if metadata:
                node.metadata.update(metadata)
            return node

        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            sources=[source] if source else [],
            metadata=metadata or {},
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        weight: float = 1.0,
        source: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> GraphEdge:
        """Add or update a co-occurrence edge between two nodes.

        Edges are undirected — (A, B) and (B, A) resolve to the same edge.
        If the edge already exists, its co_occurrences count is incremented.

        Args:
            source_id: Node ID of one endpoint.
            target_id: Node ID of the other endpoint.
            weight: Confidence weight for the co-occurrence (0.0-1.0).
            source: Optional source module name.
            metadata: Optional metadata dict to merge.
        Returns:
            The created or updated GraphEdge.

        Raises:
            KeyError: If either node_id does not exist in the graph.
        """
        if source_id not in self._nodes:
            raise KeyError(f"Node not found: {source_id}")
        if target_id not in self._nodes:
            raise KeyError(f"Node not found: {target_id}")
        if source_id == target_id:
            raise ValueError("Self-loops are not allowed")

        # Normalize to undirected key
        key = (source_id, target_id) if source_id < target_id else (target_id, source_id)

        if key in self._edges:
            edge = self._edges[key]
            edge.touch(source, weight_increment=0.05)
            if metadata:
                edge.metadata.update(metadata)
            return edge

        edge = GraphEdge(
            source_id=key[0],
            target_id=key[1],
            weight=weight,
            sources=[source] if source else [],
            metadata=metadata or {},
        )
        self._edges[key] = edge
        self._adjacency[source_id].add(target_id)
        self._adjacency[target_id].add(source_id)
        return edge

    def merge_subgraphs(self, other: IdentityGraph) -> int:
        """Merge another IdentityGraph into this one.

        Nodes and edges from `other` are merged into `self`. Existing
        nodes/edges are updated (timestamps, sources, co_occurrences).
        Returns the number of new entities (nodes + edges) added.

        Args:
            other: Another IdentityGraph instance.
        Returns:
            Count of newly added nodes + edges.
        """
        added = 0

        for node_id, node in other._nodes.items():
            if node_id not in self._nodes:
                self._nodes[node_id] = node.model_copy(deep=True)
                added += 1
            else:
                existing = self._nodes[node_id]
                existing.last_seen = max(existing.last_seen, node.last_seen)
                existing.first_seen = min(existing.first_seen, node.first_seen)
                for s in node.sources:
                    if s not in existing.sources:
                        existing.sources.append(s)
                existing.metadata.update(node.metadata)

        for key, edge in other._edges.items():
            if key not in self._edges:
                # Ensure both endpoints exist (they should after node merge)
                self._edges[key] = edge.model_copy(deep=True)
                self._adjacency[key[0]].add(key[1])
                self._adjacency[key[1]].add(key[0])
                added += 1
            else:
                existing_edge = self._edges[key]
                existing_edge.co_occurrences += edge.co_occurrences
                existing_edge.weight = min(existing_edge.weight + edge.weight * 0.1, 1.0)
                existing_edge.last_seen = max(existing_edge.last_seen, edge.last_seen)
                existing_edge.first_seen = min(existing_edge.first_seen, edge.first_seen)
                for s in edge.sources:
                    if s not in existing_edge.sources:
                        existing_edge.sources.append(s)
                existing_edge.metadata.update(edge.metadata)

        return added

    def query_neighbors(
        self,
        node_id: str,
        max_depth: int = 1,
        min_weight: float = 0.0,
    ) -> dict[str, Any]:
        """Query neighbors of a node up to a given depth.

        Args:
            node_id: The starting node ID.
            max_depth: BFS depth limit (default 1 = direct neighbors only).
            min_weight: Minimum edge weight to traverse.
        Returns:
            Dict with 'node' (the center node), 'neighbors' list,
            and 'edges' list connecting them.

        Raises:
            KeyError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise KeyError(f"Node not found: {node_id}")

        visited: set[str] = {node_id}
        frontier: set[str] = {node_id}
        result_nodes: list[GraphNode] = []
        result_edges: list[GraphEdge] = []

        for _ in range(max_depth):
            next_frontier: set[str] = set()
            for current in frontier:
                for neighbor_id in self._adjacency.get(current, set()):
                    if neighbor_id in visited:
                        continue
                    key = (current, neighbor_id) if current < neighbor_id else (neighbor_id, current)
                    edge = self._edges.get(key)
                    if edge and edge.weight >= min_weight:
                        result_nodes.append(self._nodes[neighbor_id])
                        result_edges.append(edge)
                        next_frontier.add(neighbor_id)
                        visited.add(neighbor_id)
            frontier = next_frontier

        return {
            "node": self._nodes[node_id],
            "neighbors": result_nodes,
            "edges": result_edges,
        }

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    def add_raw_attribute(
        self,
        raw_value: str,
        node_type: NodeType,
        source: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[str, GraphNode]:
        """Hash a raw attribute and add it as a node.

        Args:
            raw_value: The plaintext attribute value.
            node_type: The type of attribute.
            source: Optional source name.
            metadata: Optional metadata.
        Returns:
            Tuple of (hash_hex, GraphNode).
        """
        hash_hex = self.hash_attribute(raw_value)
        node = self.add_node(hash_hex, node_type, source=source, metadata=metadata)
        return hash_hex, node

    def add_co_occurrence(
        self,
        raw_a: str,
        type_a: NodeType,
        raw_b: str,
        type_b: NodeType,
        source: Optional[str] = None,
        weight: float = 1.0,
    ) -> tuple[str, str, GraphEdge]:
        """Hash two raw attributes, add nodes, and create a co-occurrence edge.

        Args:
            raw_a: First raw attribute value.
            type_a: NodeType for first attribute.
            raw_b: Second raw attribute value.
            type_b: NodeType for second attribute.
            source: Optional source name.
            weight: Edge confidence weight.
        Returns:
            Tuple of (hash_a, hash_b, GraphEdge).
        """
        hash_a, _ = self.add_raw_attribute(raw_a, type_a, source=source)
        hash_b, _ = self.add_raw_attribute(raw_b, type_b, source=source)
        edge = self.add_edge(hash_a, hash_b, weight=weight, source=source)
        return hash_a, hash_b, edge

    # ------------------------------------------------------------------
    # Statistics and serialization
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def get_all_edges(self) -> list[GraphEdge]:
        return list(self._edges.values())

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph to a JSON-compatible dict.

        Note: Salt is NOT serialized to prevent leakage. Only a salt
        fingerprint (truncated SHA-256) is included for verification.
        """
        salt_fp = hashlib.sha256(self._salt.encode()).hexdigest()[:16]
        return {
            "salt_fingerprint": salt_fp,
            "nodes": [n.model_dump(mode="json") for n in self._nodes.values()],
            "edges": [e.model_dump(mode="json") for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], salt: str = "") -> IdentityGraph:
        """Deserialize a graph from a dict (inverse of to_dict).

        Note: Salt must be provided separately since to_dict() no longer
        serializes it (for security). Use salt_fingerprint for verification.
        """
        graph = cls(salt=salt)
        for n in data.get("nodes", []):
            node = GraphNode(**n)
            graph._nodes[node.node_id] = node
        for e in data.get("edges", []):
            edge = GraphEdge(**e)
            key = (
                (edge.source_id, edge.target_id)
                if edge.source_id < edge.target_id
                else (edge.target_id, edge.source_id)
            )
            graph._edges[key] = edge
            graph._adjacency[edge.source_id].add(edge.target_id)
            graph._adjacency[edge.target_id].add(edge.source_id)
        return graph

    def __repr__(self) -> str:
        return (
            f"<IdentityGraph(nodes={self.node_count}, "
            f"edges={self.edge_count}, salt='{'***' if self._salt else ''}')>"
        )
