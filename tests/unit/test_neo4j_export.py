from src.modules.deep_scan.models_report import (
    IdentityEdge,
    IdentityGraph,
    IdentityNode,
)
from src.modules.identity_tracking.neo4j_export import export_neo4j_json


def test_neo4j_export_shape():
    g = IdentityGraph()
    g.nodes.append(IdentityNode(id="n1", label="alice@x.com", type="email"))
    g.edges.append(IdentityEdge(source_id="n1", target_id="n2", relationship="uses"))
    out = export_neo4j_json(g)
    assert len(out["nodes"]) == 1
    assert out["relationships"][0]["type"] == "USES"
