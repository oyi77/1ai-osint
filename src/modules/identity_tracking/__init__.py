"""ZKIT Identity Tracking module: Privacy-preserving identity correlation.

Lightweight SHA-256 hash-based protocol for cross-platform
identity linking without exposing raw PII.
"""

from src.modules.identity_tracking.identity_graph import (
    IdentityGraph,
    GraphNode,
    GraphEdge,
    NodeType,
)
from src.modules.identity_tracking.zkit_engine import (
    ZKITEngine,
    CorrelatedCluster,
    CorrelationConfidence,
    ZKITOutput,
    IngestedRecord,
)
from src.modules.identity_tracking.correlation import (
    CrossModuleCorrelator,
    CorrelationResult,
    ResolvedEntity,
    CorrelationSource,
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
]
