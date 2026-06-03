"""Tests for IdentityGraph data structure."""

import pytest
from src.modules.identity_tracking.identity_graph import (
    IdentityGraph,
    GraphNode,
    GraphEdge,
    NodeType,
)


@pytest.fixture
def graph() -> IdentityGraph:
    return IdentityGraph(salt="test-salt")


@pytest.fixture
def populated_graph() -> IdentityGraph:
    g = IdentityGraph(salt="test-salt")
    g.add_co_occurrence(
        "alice@example.com",
        NodeType.EMAIL_HASH,
        "alice_dev",
        NodeType.USERNAME_HASH,
        source="sherlock",
    )
    g.add_co_occurrence(
        "alice@example.com",
        NodeType.EMAIL_HASH,
        "+15551234567",
        NodeType.PHONE_HASH,
        source="holehe",
    )
    g.add_co_occurrence(
        "bob@test.org",
        NodeType.EMAIL_HASH,
        "bob_security",
        NodeType.USERNAME_HASH,
        source="maigret",
    )
    return g


class TestNodeType:
    def test_valid_types(self):
        assert NodeType.EMAIL_HASH == "email_hash"
        assert NodeType.USERNAME_HASH == "username_hash"
        assert NodeType.PHONE_HASH == "phone_hash"
        assert NodeType.DOMAIN_HASH == "domain_hash"


class TestGraphNode:
    def test_create(self):
        node = GraphNode(node_id="abc123", node_type=NodeType.EMAIL_HASH)
        assert node.node_id == "abc123"
        assert node.node_type == NodeType.EMAIL_HASH
        assert node.sources == []
        assert node.metadata == {}

    def test_touch_updates_timestamp(self):
        node = GraphNode(node_id="abc123", node_type=NodeType.EMAIL_HASH)
        old_ts = node.last_seen
        node.touch(source="test_module")
        assert node.last_seen >= old_ts
        assert "test_module" in node.sources

    def test_touch_no_duplicate_source(self):
        node = GraphNode(node_id="abc123", node_type=NodeType.EMAIL_HASH)
        node.touch(source="sherlock")
        node.touch(source="sherlock")
        assert node.sources.count("sherlock") == 1


class TestGraphEdge:
    def test_create(self):
        edge = GraphEdge(source_id="a", target_id="b")
        assert edge.weight == 1.0
        assert edge.co_occurrences == 1

    def test_touch_increments(self):
        edge = GraphEdge(source_id="a", target_id="b")
        edge.touch(source="test", weight_increment=0.05)
        assert edge.co_occurrences == 2
        assert edge.weight == 1.0  # capped at 1.0


class TestIdentityGraphHashing:
    def test_hash_deterministic(self, graph: IdentityGraph):
        h1 = graph.hash_attribute("alice@example.com")
        h2 = graph.hash_attribute("alice@example.com")
        assert h1 == h2

    def test_hash_different_values(self, graph: IdentityGraph):
        h1 = graph.hash_attribute("alice@example.com")
        h2 = graph.hash_attribute("bob@test.org")
        assert h1 != h2

    def test_hash_different_salts(self):
        g1 = IdentityGraph(salt="salt-a")
        g2 = IdentityGraph(salt="salt-b")
        h1 = g1.hash_attribute("alice@example.com")
        h2 = g2.hash_attribute("alice@example.com")
        assert h1 != h2

    def test_hash_is_64_hex_chars(self, graph: IdentityGraph):
        h = graph.hash_attribute("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestIdentityGraphAddNode:
    def test_add_new_node(self, graph: IdentityGraph):
        node = graph.add_node("hash1", NodeType.EMAIL_HASH, source="sherlock")
        assert node.node_id == "hash1"
        assert graph.node_count == 1

    def test_add_existing_node_updates(self, graph: IdentityGraph):
        graph.add_node("hash1", NodeType.EMAIL_HASH, source="sherlock")
        node = graph.add_node(
            "hash1", NodeType.EMAIL_HASH, source="holehe", metadata={"extra": True}
        )
        assert graph.node_count == 1
        assert "holehe" in node.sources
        assert node.metadata["extra"] is True


class TestIdentityGraphAddEdge:
    def test_add_edge(self, graph: IdentityGraph):
        graph.add_node("a", NodeType.EMAIL_HASH)
        graph.add_node("b", NodeType.USERNAME_HASH)
        edge = graph.add_edge("a", "b", source="sherlock")
        assert edge.co_occurrences == 1
        assert graph.edge_count == 1

    def test_add_duplicate_edge_increments(self, graph: IdentityGraph):
        graph.add_node("a", NodeType.EMAIL_HASH)
        graph.add_node("b", NodeType.USERNAME_HASH)
        graph.add_edge("a", "b")
        edge = graph.add_edge("a", "b")
        assert edge.co_occurrences == 2
        assert graph.edge_count == 1

    def test_edge_is_undirected(self, graph: IdentityGraph):
        graph.add_node("a", NodeType.EMAIL_HASH)
        graph.add_node("b", NodeType.USERNAME_HASH)
        graph.add_edge("a", "b")
        edge = graph.add_edge("b", "a")
        assert edge.co_occurrences == 2
        assert graph.edge_count == 1

    def test_edge_missing_node_raises(self, graph: IdentityGraph):
        graph.add_node("a", NodeType.EMAIL_HASH)
        with pytest.raises(KeyError):
            graph.add_edge("a", "nonexistent")

    def test_self_loop_raises(self, graph: IdentityGraph):
        graph.add_node("a", NodeType.EMAIL_HASH)
        with pytest.raises(ValueError, match="Self-loops"):
            graph.add_edge("a", "a")


class TestIdentityGraphMerge:
    def test_merge_disjoint(self):
        g1 = IdentityGraph(salt="s")
        g1.add_node("a", NodeType.EMAIL_HASH)
        g1.add_node("b", NodeType.USERNAME_HASH)
        g1.add_edge("a", "b")

        g2 = IdentityGraph(salt="s")
        g2.add_node("c", NodeType.PHONE_HASH)
        g2.add_node("d", NodeType.DOMAIN_HASH)
        g2.add_edge("c", "d")

        added = g1.merge_subgraphs(g2)
        assert g1.node_count == 4
        assert g1.edge_count == 2
        assert added >= 2  # at least 2 new nodes added

    def test_merge_overlapping(self):
        g1 = IdentityGraph(salt="s")
        g1.add_node("a", NodeType.EMAIL_HASH, source="src1")
        g1.add_node("b", NodeType.USERNAME_HASH)
        g1.add_edge("a", "b")

        g2 = IdentityGraph(salt="s")
        g2.add_node("a", NodeType.EMAIL_HASH, source="src2")
        g2.add_node("b", NodeType.USERNAME_HASH)
        g2.add_edge("a", "b")

        added = g1.merge_subgraphs(g2)
        assert g1.node_count == 2
        assert g1.edge_count == 1
        assert added == 0  # all existed
        assert "src2" in g1.get_node("a").sources


class TestIdentityGraphQueryNeighbors:
    def test_direct_neighbors(self, populated_graph: IdentityGraph):
        email_hash = populated_graph.hash_attribute("alice@example.com")
        result = populated_graph.query_neighbors(email_hash, max_depth=1)
        neighbor_ids = {n.node_id for n in result["neighbors"]}
        assert len(neighbor_ids) == 2  # username + phone

    def test_depth_2(self, populated_graph: IdentityGraph):
        email_hash = populated_graph.hash_attribute("alice@example.com")
        result = populated_graph.query_neighbors(email_hash, max_depth=2)
        # alice email -> alice username + alice phone (depth 1)
        # alice username has no further edges, alice phone has no further edges
        assert len(result["neighbors"]) == 2

    def test_min_weight_filter(self, populated_graph: IdentityGraph):
        email_hash = populated_graph.hash_attribute("alice@example.com")
        result = populated_graph.query_neighbors(email_hash, min_weight=0.99)
        # All edges have weight 1.0, so all pass
        assert len(result["neighbors"]) == 2

    def test_missing_node_raises(self, graph: IdentityGraph):
        with pytest.raises(KeyError):
            graph.query_neighbors("nonexistent")


class TestIdentityGraphConvenience:
    def test_add_raw_attribute(self, graph: IdentityGraph):
        hash_hex, node = graph.add_raw_attribute(
            "alice@example.com", NodeType.EMAIL_HASH, source="test"
        )
        assert len(hash_hex) == 64
        assert graph.node_count == 1
        assert node.node_id == hash_hex

    def test_add_co_occurrence(self, graph: IdentityGraph):
        h1, h2, edge = graph.add_co_occurrence(
            "alice@example.com",
            NodeType.EMAIL_HASH,
            "alice_dev",
            NodeType.USERNAME_HASH,
            source="sherlock",
        )
        assert graph.node_count == 2
        assert graph.edge_count == 1
        assert edge.source_id in (h1, h2)
        assert edge.target_id in (h1, h2)


class TestIdentityGraphQueryByType:
    def test_filter_by_type(self, populated_graph: IdentityGraph):
        emails = populated_graph.get_nodes_by_type(NodeType.EMAIL_HASH)
        assert len(emails) == 2
        assert all(n.node_type == NodeType.EMAIL_HASH for n in emails)

    def test_username_nodes(self, populated_graph: IdentityGraph):
        usernames = populated_graph.get_nodes_by_type(NodeType.USERNAME_HASH)
        assert len(usernames) == 2


class TestIdentityGraphSerialization:
    def test_roundtrip(self, populated_graph: IdentityGraph):
        data = populated_graph.to_dict()
        restored = IdentityGraph.from_dict(data, salt=populated_graph._salt)
        assert restored.node_count == populated_graph.node_count
        assert restored.edge_count == populated_graph.edge_count
        assert restored._salt == populated_graph._salt

    def test_dict_structure(self, graph: IdentityGraph):
        graph.add_node("h1", NodeType.EMAIL_HASH)
        data = graph.to_dict()
        assert "salt_fingerprint" in data
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 1

    def test_repr(self, graph: IdentityGraph):
        r = repr(graph)
        assert "IdentityGraph" in r
        assert "nodes=0" in r
