"""ZKIT Identity Tracking module: Privacy-preserving identity correlation.

Lightweight SHA-256 hash-based protocol for cross-platform
identity linking without exposing raw PII.
"""

from src.modules.identity_tracking.correlation import (
    CorrelationResult,
    CorrelationSource,
    CrossModuleCorrelator,
    ResolvedEntity,
)
from src.modules.identity_tracking.identity_graph import (
    GraphEdge,
    GraphNode,
    IdentityGraph,
    NodeType,
)
from src.modules.identity_tracking.neo4j_export import (
    Neo4jClient,
    export_neo4j_json,
    load_neo4j_json,
)
from src.modules.identity_tracking.zkit_engine import (
    CorrelatedCluster,
    CorrelationConfidence,
    IngestedRecord,
    ZKITEngine,
    ZKITOutput,
)

__all__ = [
    "IdentityGraph",
    "GraphNode",
    "GraphEdge",
    "NodeType",
    "ZKITEngine",
    "CorrelatedCluster",
    "CorrelationConfidence",
    "ZKITOutput",
    "IngestedRecord",
    "CrossModuleCorrelator",
    "CorrelationResult",
    "ResolvedEntity",
    "CorrelationSource",
    "Neo4jClient",
    "export_neo4j_json",
    "load_neo4j_json",
]
