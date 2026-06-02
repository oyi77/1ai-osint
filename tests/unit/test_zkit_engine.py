"""Tests for ZKIT Protocol Engine."""

import hashlib

import pytest

from src.modules.identity_tracking.identity_graph import NodeType
from src.modules.identity_tracking.zkit_engine import (
    CorrelatedCluster,
    CorrelationConfidence,
    ZKITEngine,
    ZKITOutput,
    _normalize_attribute,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def salt() -> str:
    return "test-salt-for-zkit-engine"


@pytest.fixture
def engine(salt: str) -> ZKITEngine:
    return ZKITEngine(salt=salt, investigation_id="test-investigation")


@pytest.fixture
def sample_records() -> list[dict]:
    return [
        {"email": "Alice@Example.com", "username": "alice_dev", "source": "sherlock"},
        {"email": "alice@example.com", "phone": "+1 555 123 4567", "source": "holehe"},
        {"email": "bob@test.org", "username": "bob_security", "source": "maigret"},
        {"domain": "https://www.Example.com/", "email": "alice@example.com", "source": "shodan"},
    ]


@pytest.fixture
def engine_with_graph(engine: ZKITEngine, sample_records: list[dict]) -> ZKITEngine:
    """Engine with graph already built from sample records."""
    ingested = engine.ingest(sample_records)
    hashed = engine.hash_records(ingested)
    engine.build_graph(hashed)
    return engine


# ---------------------------------------------------------------------------
# Test normalization
# ---------------------------------------------------------------------------

class TestNormalizeAttribute:
    def test_email_lowercased(self):
        assert _normalize_attribute("email", "Alice@Example.COM") == "alice@example.com"

    def test_email_stripped(self):
        assert _normalize_attribute("email", "  alice@test.org  ") == "alice@test.org"

    def test_domain_lowercase_no_protocol(self):
        assert _normalize_attribute("domain", "https://www.Example.com/") == "example.com"

    def test_domain_http_prefix(self):
        assert _normalize_attribute("domain", "http://test.org") == "test.org"

    def test_domain_www_prefix(self):
        assert _normalize_attribute("domain", "www.test.org") == "test.org"

    def test_phone_strips_formatting(self):
        assert _normalize_attribute("phone", "+1 (555) 123-4567") == "+15551234567"

    def test_username_as_is(self):
        assert _normalize_attribute("username", "alice_dev") == "alice_dev"


# ---------------------------------------------------------------------------
# Test salt management
# ---------------------------------------------------------------------------

class TestSaltManagement:
    def test_new_salt_is_64_hex(self):
        salt = ZKITEngine.new_salt()
        assert len(salt) == 64
        assert all(c in "0123456789abcdef" for c in salt)

    def test_new_salt_unique(self):
        salts = {ZKITEngine.new_salt() for _ in range(100)}
        assert len(salts) == 100

    def test_empty_salt_raises(self):
        with pytest.raises(ValueError, match="Salt must not be empty"):
            ZKITEngine(salt="")

    def test_salt_fingerprint_not_salt(self, engine: ZKITEngine, salt: str):
        fp = engine.salt_fingerprint
        assert len(fp) == 16
        assert fp != salt
        # Fingerprint is SHA-256 of salt, truncated
        expected = hashlib.sha256(salt.encode()).hexdigest()[:16]
        assert fp == expected

    def test_investigation_id_default(self):
        e = ZKITEngine(salt="some-salt")
        assert len(e.investigation_id) == 16  # 8 bytes hex

    def test_investigation_id_custom(self, engine: ZKITEngine):
        assert engine.investigation_id == "test-investigation"


# ---------------------------------------------------------------------------
# Test ingest stage
# ---------------------------------------------------------------------------

class TestIngest:
    def test_ingest_normalizes_email(self, engine: ZKITEngine):
        records = [{"email": "Alice@Example.COM"}]
        result = engine.ingest(records)
        assert len(result) == 1
        assert result[0].attributes["email"] == "alice@example.com"

    def test_ingest_skips_empty_records(self, engine: ZKITEngine):
        records = [{"unrelated_field": "value"}]
        result = engine.ingest(records)
        assert len(result) == 0

    def test_ingest_multiple_attributes(self, engine: ZKITEngine):
        records = [{"email": "a@b.com", "username": "ab", "phone": "+123"}]
        result = engine.ingest(records)
        assert len(result) == 1
        assert set(result[0].attributes.keys()) == {"email", "username", "phone"}

    def test_ingest_preserves_source(self, engine: ZKITEngine):
        records = [{"email": "a@b.com", "source": "sherlock"}]
        result = engine.ingest(records)
        assert result[0].source == "sherlock"

    def test_ingest_default_source(self, engine: ZKITEngine):
        records = [{"email": "a@b.com"}]
        result = engine.ingest(records, default_source="default_src")
        assert result[0].source == "default_src"

    def test_ingest_metadata_excludes_pii(self, engine: ZKITEngine):
        records = [{"email": "a@b.com", "extra_field": "keep_me"}]
        result = engine.ingest(records)
        assert "email" not in result[0].metadata
        assert result[0].metadata.get("extra_field") == "keep_me"

    def test_ingest_source_list(self, engine: ZKITEngine):
        records = [{"email": "a@b.com", "source": ["src1", "src2"]}]
        result = engine.ingest(records)
        assert result[0].source == "src1,src2"

    def test_ingest_strips_whitespace(self, engine: ZKITEngine):
        records = [{"username": "  alice  "}]
        result = engine.ingest(records)
        assert result[0].attributes["username"] == "alice"


# ---------------------------------------------------------------------------
# Test hash stage
# ---------------------------------------------------------------------------

class TestHashRecords:
    def test_hash_produces_64_char_hex(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "test@example.com"}])
        hashed = engine.hash_records(ingested)
        assert len(hashed) == 1
        email_hash = hashed[0]["email"]
        assert len(email_hash) == 64
        assert all(c in "0123456789abcdef" for c in email_hash)

    def test_hash_deterministic(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "test@example.com"}])
        h1 = engine.hash_records(ingested)
        h2 = engine.hash_records(ingested)
        assert h1[0]["email"] == h2[0]["email"]

    def test_hash_preserves_source(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "a@b.com", "source": "sherlock"}])
        hashed = engine.hash_records(ingested)
        assert hashed[0]["_source"] == "sherlock"

    def test_hash_different_salts_produce_different_hashes(self):
        e1 = ZKITEngine(salt="salt-a")
        e2 = ZKITEngine(salt="salt-b")
        ingested = e1.ingest([{"email": "test@example.com"}])
        h1 = e1.hash_records(ingested)
        h2 = e2.hash_records(ingested)
        assert h1[0]["email"] != h2[0]["email"]

    def test_hash_multiple_attributes(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "a@b.com", "username": "ab"}])
        hashed = engine.hash_records(ingested)
        assert "email" in hashed[0]
        assert "username" in hashed[0]
        assert hashed[0]["email"] != hashed[0]["username"]


# ---------------------------------------------------------------------------
# Test graph stage
# ---------------------------------------------------------------------------

class TestBuildGraph:
    def test_creates_nodes(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "a@b.com", "username": "ab"}])
        hashed = engine.hash_records(ingested)
        graph = engine.build_graph(hashed)
        assert graph.node_count == 2

    def test_creates_edges(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "a@b.com", "username": "ab"}])
        hashed = engine.hash_records(ingested)
        graph = engine.build_graph(hashed)
        assert graph.edge_count == 1

    def test_co_occurrence_increments(self, engine: ZKITEngine):
        ingested = engine.ingest([
            {"email": "a@b.com", "username": "ab", "source": "s1"},
            {"email": "a@b.com", "username": "ab", "source": "s2"},
        ])
        hashed = engine.hash_records(ingested)
        graph = engine.build_graph(hashed)
        # Same nodes, edge should be updated not duplicated
        assert graph.node_count == 2
        assert graph.edge_count == 1
        edges = graph.get_all_edges()
        assert edges[0].co_occurrences == 2

    def test_multiple_records_link_shared_nodes(self, engine: ZKITEngine):
        ingested = engine.ingest([
            {"email": "a@b.com", "username": "ab"},
            {"email": "a@b.com", "phone": "+123"},
        ])
        hashed = engine.hash_records(ingested)
        graph = engine.build_graph(hashed)
        # email node is shared, so 3 nodes: email, username, phone
        assert graph.node_count == 3
        # edges: (email, username), (email, phone) = 2
        assert graph.edge_count == 2

    def test_nodes_have_correct_types(self, engine_with_graph: ZKITEngine):
        graph = engine_with_graph.graph
        email_nodes = graph.get_nodes_by_type(NodeType.EMAIL_HASH)
        assert len(email_nodes) >= 1


# ---------------------------------------------------------------------------
# Test correlate stage
# ---------------------------------------------------------------------------

class TestCorrelate:
    def test_single_component_for_shared_email(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        # alice@example.com appears in multiple records linking email, username, phone, domain
        # They should all be in one connected component
        assert len(components) >= 1
        # Find the largest component (alice's cluster)
        largest = max(components, key=len)
        assert len(largest) >= 3  # at least email + username + phone or domain

    def test_separate_components_for_disjoint(self, engine: ZKITEngine):
        ingested = engine.ingest([
            {"email": "unrelated1@a.com", "username": "u1"},
            {"email": "unrelated2@b.com", "username": "u2"},
        ])
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)
        components = engine.correlate()
        assert len(components) == 2

    def test_empty_graph(self, engine: ZKITEngine):
        components = engine.correlate()
        assert components == []


# ---------------------------------------------------------------------------
# Test score stage
# ---------------------------------------------------------------------------

class TestScoreComponents:
    def test_score_range(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        for cluster in clusters:
            assert 0.0 <= cluster.score <= 1.0

    def test_higher_co_occurrence_higher_score(self, engine: ZKITEngine):
        # Cluster with many observations should score higher than single observation
        records = []
        for i in range(10):
            records.append({
                "email": "frequent@example.com",
                "username": "freq_user",
                "source": f"source_{i}",
            })
        ingested = engine.ingest(records)
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)
        components = engine.correlate()
        clusters = engine.score_components(components)
        assert len(clusters) == 1
        assert clusters[0].score > 0.3  # should be reasonably high
        assert clusters[0].total_co_occurrences >= 10

    def test_single_node_low_score(self, engine: ZKITEngine):
        ingested = engine.ingest([{"email": "alone@test.com"}])
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)
        components = engine.correlate()
        clusters = engine.score_components(components)
        assert len(clusters) == 1
        # Single node, no edges, single source -> low score
        assert clusters[0].score < 0.5

    def test_cluster_has_attribute_types(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        for cluster in clusters:
            assert len(cluster.attribute_types) >= 1
            assert all(
                t in ("email_hash", "username_hash", "phone_hash", "domain_hash")
                for t in cluster.attribute_types
            )

    def test_confidence_tiers(self, engine: ZKITEngine):
        # Force high diversity + high co-occurrence
        records = []
        for i in range(8):
            records.append({
                "email": "high@example.com",
                "username": "high_user",
                "phone": "+15550000000",
                "domain": "example.com",
                "source": f"src_{i}",
            })
        ingested = engine.ingest(records)
        hashed = engine.hash_records(ingested)
        engine.build_graph(hashed)
        components = engine.correlate()
        clusters = engine.score_components(components)
        assert len(clusters) == 1
        # High diversity + many sources should yield at least MEDIUM
        assert clusters[0].confidence in (CorrelationConfidence.HIGH, CorrelationConfidence.MEDIUM)

    def test_clusters_sorted_by_score_desc(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        scores = [c.score for c in clusters]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Test output / privacy enforcement
# ---------------------------------------------------------------------------

class TestProduceOutput:
    def test_output_has_no_raw_pii(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        output = engine_with_graph.produce_output(clusters)
        # Verify the output object has no PII fields
        output_str = output.__repr__()
        assert "alice@example.com" not in output_str
        assert "alice_dev" not in output_str

    def test_output_type(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        output = engine_with_graph.produce_output(clusters)
        assert isinstance(output, ZKITOutput)

    def test_output_has_salt_fingerprint_not_salt(self, engine_with_graph: ZKITEngine, salt: str):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        output = engine_with_graph.produce_output(clusters)
        assert output.salt_fingerprint != salt
        assert len(output.salt_fingerprint) == 16

    def test_output_graph_stats(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        output = engine_with_graph.produce_output(clusters)
        assert output.graph_stats["node_count"] > 0
        assert output.graph_stats["edge_count"] > 0
        assert output.graph_stats["cluster_count"] == len(clusters)

    def test_output_investigation_id(self, engine_with_graph: ZKITEngine):
        components = engine_with_graph.correlate()
        clusters = engine_with_graph.score_components(components)
        output = engine_with_graph.produce_output(clusters)
        assert output.investigation_id == "test-investigation"

    def test_privacy_enforcement_blocks_pii_in_metadata(self, engine: ZKITEngine):
        cluster = CorrelatedCluster(
            cluster_id="test",
            hash_members=["abc"],
            attribute_types={"email_hash"},
            score=0.5,
            confidence=CorrelationConfidence.MEDIUM,
            edge_count=1,
            total_co_occurrences=1,
            sources=["test"],
            metadata={"email": "raw_pii_leak@example.com"},
        )
        with pytest.raises(ValueError, match="Privacy violation"):
            engine.produce_output([cluster])


# ---------------------------------------------------------------------------
# Test full pipeline (run)
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_run_returns_zkit_output(self, engine: ZKITEngine, sample_records: list[dict]):
        output = engine.run(sample_records)
        assert isinstance(output, ZKITOutput)

    def test_run_clusters_have_hashes_not_raw(self, engine: ZKITEngine, sample_records: list[dict]):
        output = engine.run(sample_records)
        for cluster in output.clusters:
            for h in cluster.hash_members:
                assert len(h) == 64
                assert all(c in "0123456789abcdef" for c in h)

    def test_run_multiple_records(self, engine: ZKITEngine, sample_records: list[dict]):
        output = engine.run(sample_records)
        assert output.graph_stats["node_count"] >= 3
        assert len(output.clusters) >= 1

    def test_run_empty_records(self, engine: ZKITEngine):
        output = engine.run([])
        assert output.graph_stats["node_count"] == 0
        assert output.clusters == []

    def test_run_default_source(self, engine: ZKITEngine):
        output = engine.run([{"email": "a@b.com"}], default_source="default")
        assert len(output.clusters) == 1

    def test_run_no_pii_in_output_repr(self, engine: ZKITEngine, sample_records: list[dict]):
        output = engine.run(sample_records)
        output_str = repr(output)
        # Verify none of the raw values appear
        assert "alice@example.com" not in output_str
        assert "bob@test.org" not in output_str
        assert "alice_dev" not in output_str
        assert "+1 555 123 4567" not in output_str


# ---------------------------------------------------------------------------
# Test repr
# ---------------------------------------------------------------------------

class TestRepr:
    def test_engine_repr(self, engine: ZKITEngine):
        r = repr(engine)
        assert "ZKITEngine" in r
        assert "test-investigation" in r
        assert "nodes=0" in r
