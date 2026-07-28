"""ZKIT Protocol Engine — privacy-preserving identity correlation pipeline.

Implements the full ZKIT pipeline:
    ingest -> hash -> graph -> correlate -> score -> output

Per-investigation salt management, correlation scoring, and privacy
guarantee enforcement (no raw PII in output). Uses IdentityGraph
from identity_graph.py.
"""

from __future__ import annotations

import secrets
from typing import Any

from src.modules.identity_tracking._graph_models import (
    NodeType,
)
from src.modules.identity_tracking._zkit_types import (
    ATTRIBUTE_TYPE_MAP,
    PII_FIELDS,
    CorrelatedCluster,
    CorrelationConfidence,
    IngestedRecord,
    ZKITOutput,
    normalize_attribute,
)
from src.modules.identity_tracking.identity_graph import IdentityGraph

# Re-export types so existing imports (from zkit_engine import ...) don't break
CorrelatedCluster = CorrelatedCluster
CorrelationConfidence = CorrelationConfidence
IngestedRecord = IngestedRecord
ZKITOutput = ZKITOutput
ATTRIBUTE_TYPE_MAP = ATTRIBUTE_TYPE_MAP
_normalize_attribute = normalize_attribute  # noqa: SLF001


# ---------------------------------------------------------------------------
# ZKIT Engine
# ---------------------------------------------------------------------------


class ZKITEngine:
    """ZKIT Protocol engine implementing the full pipeline:
        ingest -> hash -> graph -> correlate -> score -> output

    Per-investigation salt is required. Generate with ``new_salt()`` or
    pass a caller-provided salt. The salt is NEVER included in output.
    """

    def __init__(self, salt: str, *, investigation_id: str = "") -> None:
        """Args:
        salt: Per-investigation cryptographic salt (>= 256 bits recommended).
              Must not be empty for production use.
        investigation_id: Optional label for this investigation.

        """
        if not salt:
            raise ValueError("Salt must not be empty — generate with ZKITEngine.new_salt()")
        self._salt = salt
        self._investigation_id = investigation_id or secrets.token_hex(8)
        self._graph = IdentityGraph(salt=salt)

    # ------------------------------------------------------------------
    # Salt management
    # ------------------------------------------------------------------

    @staticmethod
    def new_salt() -> str:
        """Generate a cryptographically secure 256-bit salt.

        Returns:
            64-character hex string (32 bytes = 256 bits).

        """
        return secrets.token_hex(32)

    @property
    def salt_fingerprint(self) -> str:
        """Return a non-reversible fingerprint of the salt for logging.

        Uses SHA-256 of the salt, truncated to 16 hex chars. This lets
        operators verify which salt was used without exposing the salt.
        """
        import hashlib

        return hashlib.sha256(self._salt.encode("utf-8")).hexdigest()[:16]

    @property
    def investigation_id(self) -> str:
        return self._investigation_id

    @property
    def graph(self) -> IdentityGraph:
        """Direct access to the underlying IdentityGraph (read-mostly)."""
        return self._graph

    # ------------------------------------------------------------------
    # Pipeline stage 1: INGEST
    # ------------------------------------------------------------------

    def ingest(
        self,
        records: list[dict[str, Any]],
        *,
        default_source: str = "unknown",
    ) -> list[IngestedRecord]:
        """Ingest raw records and normalize attribute values.

        Each record dict should contain identity attribute keys
        (email, username, phone, domain) plus optional 'source' and 'metadata'.

        Args:
            records: List of raw record dicts.
            default_source: Fallback source name if record has none.

        Returns:
            List of IngestedRecord with normalized attributes.

        """
        ingested: list[IngestedRecord] = []
        for rec in records:
            attrs: dict[str, str] = {}
            for attr_type in ATTRIBUTE_TYPE_MAP:
                raw = rec.get(attr_type)
                if raw and isinstance(raw, str) and raw.strip():
                    attrs[attr_type] = normalize_attribute(attr_type, raw)

            if not attrs:
                continue  # skip records with no recognizable attributes

            source = rec.get("source", default_source)
            if isinstance(source, list):
                source = ",".join(source)

            # Metadata: copy everything that is NOT a PII field or source
            meta = {k: v for k, v in rec.items() if k not in PII_FIELDS and k != "source"}

            ingested.append(
                IngestedRecord(
                    attributes=attrs,
                    source=str(source),
                    metadata=meta,
                )
            )

        return ingested

    # ------------------------------------------------------------------
    # Pipeline stage 2: HASH
    # ------------------------------------------------------------------

    def hash_records(self, records: list[IngestedRecord]) -> list[dict[str, str]]:
        """Hash all attributes in ingested records using ZKIT protocol.

        Args:
            records: Normalized IngestedRecord list.

        Returns:
            List of dicts mapping attr_type -> zkit_hash. Source preserved
            under '_source' key for downstream use.

        """
        hashed: list[dict[str, str]] = []
        for rec in records:
            entry: dict[str, str] = {}
            for attr_type, raw_value in rec.attributes.items():
                zkit_hash = self._hash_attribute(raw_value)
                entry[attr_type] = zkit_hash
            entry["_source"] = rec.source
            hashed.append(entry)
        return hashed

    def _hash_attribute(self, value: str) -> str:
        """Hash a single attribute using ZKIT protocol: H(S : attr)."""
        return self._graph.hash_attribute(value)

    # ------------------------------------------------------------------
    # Pipeline stage 3: GRAPH
    # ------------------------------------------------------------------

    def build_graph(self, hashed_records: list[dict[str, str]]) -> IdentityGraph:
        """Build identity graph from hashed records.

        Each hashed record becomes a set of nodes (one per attribute type)
        with co-occurrence edges linking all attributes in the same record.

        Args:
            hashed_records: Output of hash_records().

        Returns:
            The populated IdentityGraph (same instance as self._graph).

        """
        for entry in hashed_records:
            source = entry.get("_source", "")
            hashes: list[tuple[str, NodeType]] = []

            for attr_type, zkit_hash in entry.items():
                if attr_type.startswith("_"):
                    continue
                node_type = ATTRIBUTE_TYPE_MAP.get(attr_type, NodeType.USERNAME_HASH)
                self._graph.add_node(zkit_hash, node_type, source=source)
                hashes.append((zkit_hash, node_type))

            # Create co-occurrence edges between all attribute pairs in this record
            for i in range(len(hashes)):
                for j in range(i + 1, len(hashes)):
                    self._graph.add_edge(
                        hashes[i][0],
                        hashes[j][0],
                        weight=1.0,
                        source=source,
                    )

        return self._graph

    # ------------------------------------------------------------------
    # Pipeline stage 4: CORRELATE
    # ------------------------------------------------------------------

    def correlate(self, graph: IdentityGraph | None = None) -> list[set[str]]:
        """Find connected components in the identity graph.

        Each connected component represents a set of hashed attributes
        that may belong to the same entity.

        Args:
            graph: Graph to analyze. Defaults to self._graph.

        Returns:
            List of sets, each containing node_ids in one component.

        """
        g = graph or self._graph
        visited: set[str] = set()
        components: list[set[str]] = []

        for node_id in (n.node_id for n in g.get_all_nodes()):
            if node_id in visited:
                continue
            # BFS to find full connected component
            component: set[str] = set()
            frontier = [node_id]
            while frontier:
                current = frontier.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                result = g.query_neighbors(current, max_depth=1)
                for neighbor in result["neighbors"]:
                    if neighbor.node_id not in visited:
                        frontier.append(neighbor.node_id)
            components.append(component)

        return components

    # ------------------------------------------------------------------
    # Pipeline stage 5: SCORE
    # ------------------------------------------------------------------

    def score_components(
        self,
        components: list[set[str]],
        graph: IdentityGraph | None = None,
    ) -> list[CorrelatedCluster]:
        """Compute correlation confidence scores for each component.

        Scoring factors:
        - Edge density: more edges relative to nodes = stronger correlation
        - Co-occurrence count: repeated independent observations boost score
        - Attribute diversity: more distinct attribute types = higher confidence
        - Source diversity: observations from more independent sources = higher confidence

        Final score = weighted combination, clamped to [0.0, 1.0].

        Args:
            components: Output of correlate().
            graph: Graph to score against. Defaults to self._graph.

        Returns:
            List of CorrelatedCluster with computed scores.

        """
        g = graph or self._graph
        clusters: list[CorrelatedCluster] = []

        for idx, component in enumerate(components):
            if len(component) < 1:
                continue

            # Gather edges within this component
            all_edges = g.get_all_edges()
            component_edges = [e for e in all_edges if e.source_id in component and e.target_id in component]

            edge_count = len(component_edges)
            total_co_occurrences = sum(e.co_occurrences for e in component_edges)
            avg_edge_weight = sum(e.weight for e in component_edges) / edge_count if edge_count > 0 else 0.0

            # Attribute type diversity
            attr_types: set[str] = set()
            all_sources: set[str] = set()
            for node_id in component:
                node = g.get_node(node_id)
                if node:
                    attr_types.add(node.node_type.value)
                    all_sources.update(node.sources)

            # Scoring algorithm
            n_nodes = len(component)
            n_types = len(attr_types)
            n_sources = len(all_sources)

            # Edge density: ratio of actual edges to max possible edges
            max_edges = n_nodes * (n_nodes - 1) / 2 if n_nodes > 1 else 1
            edge_density = edge_count / max_edges if max_edges > 0 else 0.0

            # Co-occurrence strength: log-scaled, capped
            import math

            co_occ_score = min(math.log2(total_co_occurrences + 1) / 6.0, 1.0)

            # Type diversity: more types = stronger signal (max ~4 types)
            type_diversity = min(n_types / 4.0, 1.0)

            # Source diversity: more independent sources = stronger
            source_diversity = min(n_sources / 5.0, 1.0)

            # Weighted combination
            score = 0.30 * edge_density + 0.25 * co_occ_score + 0.25 * type_diversity + 0.20 * source_diversity

            # Bonus for having high average edge weight
            score = score * 0.8 + avg_edge_weight * 0.2
            score = max(0.0, min(1.0, score))

            # Determine confidence tier
            if score >= 0.75:
                confidence = CorrelationConfidence.HIGH
            elif score >= 0.4:
                confidence = CorrelationConfidence.MEDIUM
            else:
                confidence = CorrelationConfidence.LOW

            clusters.append(
                CorrelatedCluster(
                    cluster_id=f"cluster-{idx:04d}",
                    hash_members=sorted(component),
                    attribute_types=attr_types,
                    score=round(score, 4),
                    confidence=confidence,
                    edge_count=edge_count,
                    total_co_occurrences=total_co_occurrences,
                    sources=sorted(all_sources),
                )
            )

        # Sort by score descending
        clusters.sort(key=lambda c: c.score, reverse=True)
        return clusters

    # ------------------------------------------------------------------
    # Pipeline stage 6: OUTPUT
    # ------------------------------------------------------------------

    def produce_output(
        self,
        clusters: list[CorrelatedCluster],
    ) -> ZKITOutput:
        """Produce final sanitized output.

        Privacy guarantee: no raw PII appears in the output. Only
        zkit hashes, attribute types, and correlation metadata are included.

        Args:
            clusters: Scored clusters from score_components().

        Returns:
            ZKITOutput with sanitized data.

        """
        # Validate no PII leaked into cluster metadata
        for cluster in clusters:
            self._enforce_privacy(cluster.metadata)

        return ZKITOutput(
            investigation_id=self._investigation_id,
            salt_fingerprint=self.salt_fingerprint,
            clusters=clusters,
            graph_stats={
                "node_count": self._graph.node_count,
                "edge_count": self._graph.edge_count,
                "cluster_count": len(clusters),
                "investigation_id": self._investigation_id,
                "salt_fingerprint": self.salt_fingerprint,
            },
        )

    @staticmethod
    def _enforce_privacy(data: dict[str, Any]) -> None:
        """Verify that a dict contains no raw PII fields.

        Raises:
            ValueError: If a known PII field is found.

        """
        for key in data:
            if key.lower() in PII_FIELDS:
                raise ValueError(f"Privacy violation: PII field '{key}' found in output metadata")

    # ------------------------------------------------------------------
    # Full pipeline convenience
    # ------------------------------------------------------------------

    def run(
        self,
        records: list[dict[str, Any]],
        *,
        default_source: str = "unknown",
    ) -> ZKITOutput:
        """Execute the full ZKIT pipeline end-to-end.

        Args:
            records: Raw record dicts with identity attributes.
            default_source: Fallback source name.

        Returns:
            Sanitized ZKITOutput with scored correlation clusters.

        """
        ingested = self.ingest(records, default_source=default_source)
        hashed = self.hash_records(ingested)
        self.build_graph(hashed)
        components = self.correlate()
        clusters = self.score_components(components)
        return self.produce_output(clusters)

    def __repr__(self) -> str:
        return (
            f"<ZKITEngine(investigation='{self._investigation_id}', "
            f"salt_fp='{self.salt_fingerprint}', "
            f"nodes={self._graph.node_count}, edges={self._graph.edge_count})>"
        )
