"""Cross-module correlation engine using ZKIT identity graph.

Links identities across all module outputs using IdentityGraph for
privacy-preserving entity resolution. Computes confidence scores for
correlations and resolves same-person entities across platforms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.core.models import ScanResult
from src.modules.identity_tracking.identity_graph import (
    IdentityGraph,
)
from src.modules.identity_tracking.zkit_engine import (
    ATTRIBUTE_TYPE_MAP,
    CorrelatedCluster,
    ZKITEngine,
)


class CorrelationSource(str, Enum):
    """Sources that can contribute identity data."""

    DATA_LEAKS = "data_leaks"
    PEOPLE_FINDER = "people_finder"
    PHONE_FINDER = "phone_finder"
    GITLEAKS = "gitleaks"
    ENTITY_EXTRACTION = "entity_extraction"
    MANUAL = "manual"


@dataclass
class ResolvedEntity:
    """A resolved entity representing one real-world identity."""

    entity_id: str
    zkit_hashes: list[str]
    attribute_types: dict[str, str]  # hash -> NodeType value
    confidence: float  # [0.0, 1.0]
    source_modules: list[str]
    correlation_evidence: list[str]  # human-readable evidence
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationResult:
    """Result of cross-module correlation analysis."""

    resolved_entities: list[ResolvedEntity]
    graph_stats: dict[str, Any]
    unresolved_hashes: list[str]  # hashes not linked to any entity
    investigation_id: str = ""


class CrossModuleCorrelator:
    """Links identities across all module outputs using ZKIT graph.

    Uses IdentityGraph for privacy-preserving graph operations and
    ZKITEngine for hashing and pipeline stages. Produces resolved
    entities with confidence scores for same-person identification.

    Usage:
        correlator = CrossModuleCorrelator(salt="investigation-salt")
        correlator.ingest_scan_results(module_results)
        result = correlator.correlate()
    """

    def __init__(
        self,
        salt: str,
        *,
        investigation_id: str = "",
        min_confidence: float = 0.1,
    ) -> None:
        """
        Args:
            salt: Per-investigation cryptographic salt (must be non-empty).
            investigation_id: Optional investigation label.
            min_confidence: Minimum confidence threshold for resolved entities.
        """
        if not salt:
            raise ValueError("Salt must not be empty")
        self._salt = salt
        self._min_confidence = min_confidence
        self._engine = ZKITEngine(salt=salt, investigation_id=investigation_id)
        self._graph = self._engine.graph
        # Track module contributions per hash
        self._hash_sources: dict[str, set[str]] = {}
        # Track raw attribute type per hash
        self._hash_types: dict[str, str] = {}

    @property
    def graph(self) -> IdentityGraph:
        """Direct access to the underlying identity graph."""
        return self._graph

    @property
    def engine(self) -> ZKITEngine:
        """Direct access to the ZKIT engine."""
        return self._engine

    # ------------------------------------------------------------------
    # Ingestion from ScanResult objects
    # ------------------------------------------------------------------

    def ingest_scan_results(
        self,
        module_results: dict[str, ScanResult],
    ) -> int:
        """Ingest ScanResult objects from multiple modules.

        Each ScanResult's findings and breach_records are extracted,
        hashed, and added to the identity graph.

        Args:
            module_results: Dict mapping module name to ScanResult.

        Returns:
            Number of identity records ingested.
        """
        total_ingested = 0

        for module_name, scan_result in module_results.items():
            records = self._extract_records(scan_result, module_name)
            if records:
                ingested = self._engine.ingest(records, default_source=module_name)
                hashed = self._engine.hash_records(ingested)
                self._engine.build_graph(hashed)

                # Track sources per hash
                for entry in hashed:
                    source = entry.get("_source", module_name)
                    for attr_type, zkit_hash in entry.items():
                        if attr_type.startswith("_"):
                            continue
                        self._hash_sources.setdefault(zkit_hash, set()).add(source)
                        self._hash_types[zkit_hash] = attr_type

                total_ingested += len(ingested)

        return total_ingested

    def ingest_raw_records(
        self,
        records: list[dict[str, Any]],
        *,
        source: str = "manual",
    ) -> int:
        """Ingest raw identity records directly.

        Args:
            records: List of dicts with identity attribute keys.
            source: Source label for these records.

        Returns:
            Number of records ingested.
        """
        ingested = self._engine.ingest(records, default_source=source)
        hashed = self._engine.hash_records(ingested)
        self._engine.build_graph(hashed)

        for entry in hashed:
            entry_source = entry.get("_source", source)
            for attr_type, zkit_hash in entry.items():
                if attr_type.startswith("_"):
                    continue
                self._hash_sources.setdefault(zkit_hash, set()).add(entry_source)
                self._hash_types[zkit_hash] = attr_type

        return len(ingested)

    def _extract_records(
        self,
        scan_result: ScanResult,
        module_name: str,
    ) -> list[dict[str, Any]]:
        """Extract identity records from a ScanResult."""
        records: list[dict[str, Any]] = []

        # Extract from findings' raw_data
        for finding in scan_result.findings:
            record = self._extract_from_raw_data(finding.raw_data, module_name)
            if record:
                records.append(record)

        # Extract from breach records
        for breach in scan_result.breach_records:
            breach_record: dict[str, Any] = {"source": module_name}
            has_attr = False
            if breach.email:
                breach_record["email"] = breach.email
                has_attr = True
            if breach.username:
                breach_record["username"] = breach.username
                has_attr = True
            if breach.phone:
                breach_record["phone"] = breach.phone
                has_attr = True
            if breach.domain:
                breach_record["domain"] = breach.domain
                has_attr = True
            if has_attr:
                records.append(breach_record)

        # Extract from identities
        for identity in scan_result.identities:
            if identity.attributes:
                record = {**identity.attributes, "source": module_name}
                records.append(record)

        return records

    @staticmethod
    def _extract_from_raw_data(
        raw_data: dict[str, Any],
        source: str,
    ) -> Optional[dict[str, Any]]:
        """Extract identity attributes from a finding's raw_data."""
        record: dict[str, Any] = {"source": source}
        has_attr = False
        for attr_type in ATTRIBUTE_TYPE_MAP:
            value = raw_data.get(attr_type)
            if value and isinstance(value, str) and value.strip():
                record[attr_type] = value
                has_attr = True
        return record if has_attr else None

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate(self) -> CorrelationResult:
        """Run cross-module correlation on ingested data.

        Finds connected components in the identity graph, scores them,
        and resolves entities with confidence scores.

        Returns:
            CorrelationResult with resolved entities and stats.
        """
        components = self._engine.correlate()
        clusters = self._engine.score_components(components)

        resolved: list[ResolvedEntity] = []
        all_resolved_hashes: set[str] = set()

        for cluster in clusters:
            if cluster.score < self._min_confidence:
                continue

            entity = self._resolve_entity(cluster)
            resolved.append(entity)
            all_resolved_hashes.update(entity.zkit_hashes)

        # Find unresolved hashes
        all_hashes = {n.node_id for n in self._graph.get_all_nodes()}
        unresolved = sorted(all_hashes - all_resolved_hashes)

        return CorrelationResult(
            resolved_entities=resolved,
            graph_stats={
                "node_count": self._graph.node_count,
                "edge_count": self._graph.edge_count,
                "entity_count": len(resolved),
                "unresolved_count": len(unresolved),
            },
            unresolved_hashes=unresolved,
            investigation_id=self._engine.investigation_id,
        )

    def _resolve_entity(self, cluster: CorrelatedCluster) -> ResolvedEntity:
        """Resolve a correlated cluster into a ResolvedEntity."""
        # Gather source modules
        source_modules: set[str] = set()
        for h in cluster.hash_members:
            sources = self._hash_sources.get(h, set())
            source_modules.update(sources)

        # Gather attribute type mapping
        attribute_types: dict[str, str] = {}
        for h in cluster.hash_members:
            attr_type = self._hash_types.get(h, "unknown")
            attribute_types[h] = attr_type

        # Build evidence
        evidence = self._build_evidence(cluster, source_modules)

        return ResolvedEntity(
            entity_id=cluster.cluster_id,
            zkit_hashes=cluster.hash_members,
            attribute_types=attribute_types,
            confidence=cluster.score,
            source_modules=sorted(source_modules),
            correlation_evidence=evidence,
            metadata={
                "edge_count": cluster.edge_count,
                "total_co_occurrences": cluster.total_co_occurrences,
                "confidence_tier": cluster.confidence.value,
            },
        )

    def _build_evidence(
        self,
        cluster: CorrelatedCluster,
        source_modules: set[str],
    ) -> list[str]:
        """Build human-readable evidence lines for a correlation."""
        evidence: list[str] = []

        # Attribute diversity evidence
        type_names = sorted(cluster.attribute_types)
        if len(type_names) > 1:
            evidence.append(f"Linked attribute types: {', '.join(type_names)}")

        # Co-occurrence evidence
        if cluster.total_co_occurrences > 1:
            evidence.append(
                f"Observed {cluster.total_co_occurrences} co-occurrences " f"across {cluster.edge_count} edges"
            )

        # Cross-module evidence
        if len(source_modules) > 1:
            evidence.append(f"Confirmed across modules: {', '.join(sorted(source_modules))}")

        # Confidence evidence
        evidence.append(f"Confidence: {cluster.confidence.value} (score={cluster.score:.4f})")

        return evidence

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def find_entity_by_hash(self, zkit_hash: str) -> Optional[ResolvedEntity]:
        """Find the resolved entity containing a given hash.

        Args:
            zkit_hash: The ZKIT hash to look up.

        Returns:
            ResolvedEntity if found, None otherwise.
        """
        result = self.correlate()
        for entity in result.resolved_entities:
            if zkit_hash in entity.zkit_hashes:
                return entity
        return None

    def get_neighbors(
        self,
        zkit_hash: str,
        max_depth: int = 1,
        min_weight: float = 0.0,
    ) -> dict[str, Any]:
        """Query neighbors of a hash node in the identity graph.

        Args:
            zkit_hash: Starting node hash.
            max_depth: BFS depth limit.
            min_weight: Minimum edge weight to traverse.

        Returns:
            Dict with 'node', 'neighbors', and 'edges'.
        """
        return self._graph.query_neighbors(zkit_hash, max_depth, min_weight)

    def merge_graph(self, other: IdentityGraph) -> int:
        """Merge another IdentityGraph into the correlator's graph.

        Args:
            other: Another IdentityGraph (must share the same salt).

        Returns:
            Number of new entities added.
        """
        return self._graph.merge_subgraphs(other)
