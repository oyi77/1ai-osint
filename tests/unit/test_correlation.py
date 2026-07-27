"""Tests for cross-module correlation engine."""

import pytest

from src.core.models import BreachRecord, Finding, ScanResult, Severity
from src.modules.identity_tracking.correlation import (
    CorrelationResult,
    CrossModuleCorrelator,
)
from src.modules.identity_tracking.identity_graph import IdentityGraph, NodeType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def salt() -> str:
    return "test-correlation-salt"


@pytest.fixture
def correlator(salt: str) -> CrossModuleCorrelator:
    return CrossModuleCorrelator(salt=salt, investigation_id="test-corr")


@pytest.fixture
def sample_module_results() -> dict[str, ScanResult]:
    """Multi-module results with shared identity attributes."""
    return {
        "data_leaks": ScanResult(
            scan_id="scan-leaks",
            module="data_leaks",
            target="alice@example.com",
            status="ok",
            findings=[
                Finding(
                    id="f1",
                    module="data_leaks",
                    title="Exposed email",
                    severity=Severity.HIGH,
                    raw_data={"email": "alice@example.com", "username": "alice_dev"},
                    confidence=0.9,
                ),
            ],
            breach_records=[
                BreachRecord(
                    source="breach_db",
                    email="alice@example.com",
                    username="alice_dev",
                    domain="example.com",
                    severity=Severity.HIGH,
                ),
            ],
        ),
        "people_finder": ScanResult(
            scan_id="scan-people",
            module="people_finder",
            target="alice_dev",
            status="ok",
            findings=[
                Finding(
                    id="f2",
                    module="people_finder",
                    title="Social profile",
                    severity=Severity.INFO,
                    raw_data={
                        "email": "alice@example.com",
                        "phone": "+15551234567",
                        "username": "alice_dev",
                    },
                    confidence=0.85,
                ),
            ],
        ),
        "phone_finder": ScanResult(
            scan_id="scan-phone",
            module="phone_finder",
            target="+15551234567",
            status="ok",
            findings=[
                Finding(
                    id="f3",
                    module="phone_finder",
                    title="Phone lookup",
                    severity=Severity.INFO,
                    raw_data={"phone": "+15551234567", "email": "alice@example.com"},
                    confidence=0.8,
                ),
            ],
        ),
    }


@pytest.fixture
def disjoint_module_results() -> dict[str, ScanResult]:
    """Module results with no shared attributes."""
    return {
        "module_a": ScanResult(
            scan_id="scan-a",
            module="module_a",
            target="user_a@test.com",
            status="ok",
            findings=[
                Finding(
                    id="fa",
                    module="module_a",
                    title="Finding A",
                    severity=Severity.LOW,
                    raw_data={"email": "user_a@test.com", "username": "user_a"},
                ),
            ],
        ),
        "module_b": ScanResult(
            scan_id="scan-b",
            module="module_b",
            target="user_b@other.com",
            status="ok",
            findings=[
                Finding(
                    id="fb",
                    module="module_b",
                    title="Finding B",
                    severity=Severity.LOW,
                    raw_data={"email": "user_b@other.com", "username": "user_b"},
                ),
            ],
        ),
    }


# ---------------------------------------------------------------------------
# Test initialization
# ---------------------------------------------------------------------------


class TestCrossModuleCorrelatorInit:
    def test_create_with_salt(self, salt: str):
        c = CrossModuleCorrelator(salt=salt)
        assert c.graph.node_count == 0

    def test_empty_salt_raises(self):
        with pytest.raises(ValueError, match="Salt must not be empty"):
            CrossModuleCorrelator(salt="")

    def test_custom_investigation_id(self, salt: str):
        c = CrossModuleCorrelator(salt=salt, investigation_id="my-inv")
        assert c.engine.investigation_id == "my-inv"

    def test_graph_accessor(self, correlator: CrossModuleCorrelator):
        assert isinstance(correlator.graph, IdentityGraph)

    def test_engine_accessor(self, correlator: CrossModuleCorrelator):
        assert correlator.engine is not None


# ---------------------------------------------------------------------------
# Test ingestion from ScanResults
# ---------------------------------------------------------------------------


class TestIngestScanResults:
    def test_ingest_returns_count(self, correlator: CrossModuleCorrelator, sample_module_results):
        count = correlator.ingest_scan_results(sample_module_results)
        assert count > 0

    def test_ingest_populates_graph(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        assert correlator.graph.node_count > 0
        assert correlator.graph.edge_count > 0

    def test_ingest_creates_nodes_for_all_attributes(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        # alice@example.com, alice_dev, +15551234567, example.com
        email_nodes = correlator.graph.get_nodes_by_type(NodeType.EMAIL_HASH)
        username_nodes = correlator.graph.get_nodes_by_type(NodeType.USERNAME_HASH)
        phone_nodes = correlator.graph.get_nodes_by_type(NodeType.PHONE_HASH)
        assert len(email_nodes) >= 1
        assert len(username_nodes) >= 1
        assert len(phone_nodes) >= 1

    def test_ingest_empty_results(self, correlator: CrossModuleCorrelator):
        count = correlator.ingest_scan_results({})
        assert count == 0
        assert correlator.graph.node_count == 0

    def test_ingest_findings_and_breach_records(self, correlator: CrossModuleCorrelator, sample_module_results):
        """Both findings.raw_data and breach_records contribute attributes."""
        correlator.ingest_scan_results(sample_module_results)
        # domain comes from breach_record in data_leaks module
        domain_nodes = correlator.graph.get_nodes_by_type(NodeType.DOMAIN_HASH)
        assert len(domain_nodes) >= 1

    def test_ingest_raw_records(self, correlator: CrossModuleCorrelator):
        records = [
            {"email": "raw@test.com", "username": "raw_user", "source": "manual"},
        ]
        count = correlator.ingest_raw_records(records, source="manual")
        assert count == 1
        assert correlator.graph.node_count >= 2


# ---------------------------------------------------------------------------
# Test correlation
# ---------------------------------------------------------------------------


class TestCorrelate:
    def test_correlate_returns_result(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        assert isinstance(result, CorrelationResult)

    def test_correlate_finds_linked_entity(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        assert len(result.resolved_entities) >= 1

    def test_correlate_shared_attributes_same_entity(self, correlator: CrossModuleCorrelator, sample_module_results):
        """alice@example.com links data_leaks, people_finder, phone_finder."""
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        # All alice's attributes should be in one entity
        largest = max(result.resolved_entities, key=lambda e: len(e.zkit_hashes))
        assert len(largest.zkit_hashes) >= 3  # email, username, phone, domain

    def test_correlate_cross_module_sources(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        largest = max(result.resolved_entities, key=lambda e: len(e.zkit_hashes))
        assert len(largest.source_modules) >= 2

    def test_correlate_disjoint_produces_separate_entities(
        self, correlator: CrossModuleCorrelator, disjoint_module_results
    ):
        correlator.ingest_scan_results(disjoint_module_results)
        result = correlator.correlate()
        assert len(result.resolved_entities) == 2

    def test_correlate_empty_graph(self, correlator: CrossModuleCorrelator):
        result = correlator.correlate()
        assert result.resolved_entities == []
        assert result.unresolved_hashes == []

    def test_correlate_confidence_scores(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            assert 0.0 <= entity.confidence <= 1.0

    def test_correlate_graph_stats(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        assert result.graph_stats["node_count"] > 0
        assert result.graph_stats["edge_count"] > 0
        assert result.graph_stats["entity_count"] == len(result.resolved_entities)

    def test_correlate_unresolved_hashes(self, correlator: CrossModuleCorrelator, sample_module_results):
        """Hashes below min_confidence appear in unresolved list."""
        correlator = CrossModuleCorrelator(
            salt="test-correlation-salt",
            investigation_id="test-corr",
            min_confidence=0.99,  # very high threshold
        )
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        # With very high threshold, most/all hashes should be unresolved
        total_hashes = sum(len(e.zkit_hashes) for e in result.resolved_entities)
        total_hashes += len(result.unresolved_hashes)
        assert total_hashes == correlator.graph.node_count

    def test_correlate_investigation_id(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        assert result.investigation_id == "test-corr"


# ---------------------------------------------------------------------------
# Test resolved entities
# ---------------------------------------------------------------------------


class TestResolvedEntity:
    def test_entity_has_hashes(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            assert len(entity.zkit_hashes) >= 1
            for h in entity.zkit_hashes:
                assert len(h) == 64

    def test_entity_has_attribute_types(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            assert len(entity.attribute_types) >= 1

    def test_entity_has_evidence(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            assert len(entity.correlation_evidence) >= 1

    def test_entity_confidence_in_metadata(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            assert "confidence_tier" in entity.metadata

    def test_entity_no_raw_pii(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            entity_str = repr(entity)
            assert "alice@example.com" not in entity_str
            assert "+15551234567" not in entity_str


# ---------------------------------------------------------------------------
# Test query helpers
# ---------------------------------------------------------------------------


class TestQueryHelpers:
    def test_find_entity_by_hash(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        # Get a hash from the graph
        all_nodes = correlator.graph.get_all_nodes()
        first_hash = all_nodes[0].node_id
        entity = correlator.find_entity_by_hash(first_hash)
        if entity is not None:  # may be below min_confidence
            assert first_hash in entity.zkit_hashes

    def test_find_entity_by_hash_not_found(self, correlator: CrossModuleCorrelator):
        entity = correlator.find_entity_by_hash("nonexistent_hash_64_chars_" + "a" * 38)
        assert entity is None

    def test_get_neighbors(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        all_nodes = correlator.graph.get_all_nodes()
        first_hash = all_nodes[0].node_id
        result = correlator.get_neighbors(first_hash)
        assert "node" in result
        assert "neighbors" in result
        assert "edges" in result

    def test_merge_graph(self, correlator: CrossModuleCorrelator):
        other = IdentityGraph(salt="test-correlation-salt")
        other.add_raw_attribute("merge@test.com", NodeType.EMAIL_HASH, source="external")
        added = correlator.merge_graph(other)
        assert added >= 1
        assert correlator.graph.node_count >= 1


# ---------------------------------------------------------------------------
# Test evidence building
# ---------------------------------------------------------------------------


class TestEvidenceBuilding:
    def test_multi_type_evidence(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        largest = max(result.resolved_entities, key=lambda e: len(e.zkit_hashes))
        evidence_text = " ".join(largest.correlation_evidence)
        assert "Linked attribute types" in evidence_text or "co-occurrences" in evidence_text

    def test_cross_module_evidence(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        largest = max(result.resolved_entities, key=lambda e: len(e.zkit_hashes))
        evidence_text = " ".join(largest.correlation_evidence)
        assert "Confirmed across modules" in evidence_text

    def test_confidence_in_evidence(self, correlator: CrossModuleCorrelator, sample_module_results):
        correlator.ingest_scan_results(sample_module_results)
        result = correlator.correlate()
        for entity in result.resolved_entities:
            evidence_text = " ".join(entity.correlation_evidence)
            assert "Confidence:" in evidence_text
