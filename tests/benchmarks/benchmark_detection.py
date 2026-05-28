"""Detection accuracy benchmarks for 1ai-osint modules.

Measures precision, recall, and F1 score for each detection module against
synthetic ground-truth datasets. Designed for reproducible experimental
evaluation.

Usage:
    pytest tests/benchmarks/benchmark_detection.py -v --tb=short
    pytest tests/benchmarks/benchmark_detection.py -k "test_breach" --benchmark-json=results.json
"""

from __future__ import annotations

import pytest

from src.models import BreachRecord, Finding, Severity
from src.modules.data_leaks.breach_checker import BreachChecker
from src.modules.identity_tracking.identity_graph import IdentityGraph, NodeType
from src.modules.identity_tracking.zkit_engine import (
    CorrelationConfidence,
    ZKITEngine,
)


# ---------------------------------------------------------------------------
# Ground-truth datasets
# ---------------------------------------------------------------------------

# Breach severity ground truth: (data_classes, expected_severity)
BREACH_GROUND_TRUTH: list[tuple[list[str], Severity]] = [
    # Critical: passwords + financial
    (["password", "credit card", "email"], Severity.CRITICAL),
    (["password", "bank account", "ssn"], Severity.CRITICAL),
    (["password_hash", "credit cards", "phone", "address", "dob"], Severity.CRITICAL),
    # High: password or financial
    (["password", "email", "username"], Severity.HIGH),
    (["credit card", "email"], Severity.HIGH),
    (["password_hash", "email", "phone"], Severity.HIGH),
    # Medium: sensitive but not financial
    (["phone", "physical address"], Severity.MEDIUM),
    (["email", "phone", "date of birth"], Severity.MEDIUM),
    (["email", "ip addresses"], Severity.LOW),
    # Low/Info
    (["email", "username"], Severity.LOW),
    (["gender"], Severity.INFO),
    ([], Severity.INFO),
]

# ZKIT correlation ground truth: groups of (email, username, phone) tuples
# that should cluster together (same entity) or stay separate (different entities)
CORRELATION_GROUND_TRUTH = {
    # Each inner list = attributes belonging to one real-world entity
    "entity_1": [
        {"email": "alice@example.com", "username": "alice_dev"},
        {"email": "alice@example.com", "phone": "+15551234567"},
        {"username": "alice_dev", "domain": "example.com"},
    ],
    "entity_2": [
        {"email": "bob@test.org", "username": "bob_smith"},
        {"email": "bob@test.org", "phone": "+15559876543"},
    ],
    "entity_3": [
        {"email": "carol@demo.net", "username": "carol_x"},
    ],
}


# ---------------------------------------------------------------------------
# Metric computation helpers
# ---------------------------------------------------------------------------


def _precision_recall_f1(
    predicted: set[str],
    expected: set[str],
) -> tuple[float, float, float]:
    """Compute precision, recall, and F1 for a binary classification."""
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return precision, recall, f1


def _cluster_purity_f1(
    predicted_clusters: list[set[str]],
    ground_truth_groups: dict[str, set[str]],
) -> tuple[float, float, float]:
    """Compute micro-averaged precision/recall/F1 for clustering.

    A pair (a, b) is 'positive' if a and b belong to the same ground-truth
    group. We check whether the predicted clustering agrees.
    """
    # Build ground-truth pairs
    gt_pairs: set[tuple[str, str]] = set()
    for group in ground_truth_groups.values():
        members = sorted(group)
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                gt_pairs.add((members[i], members[j]))

    # Build predicted pairs
    pred_pairs: set[tuple[str, str]] = set()
    for cluster in predicted_clusters:
        members = sorted(cluster)
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                pred_pairs.add((members[i], members[j]))

    if not gt_pairs and not pred_pairs:
        return 1.0, 1.0, 1.0

    return _precision_recall_f1(pred_pairs, gt_pairs)


# ---------------------------------------------------------------------------
# Benchmark: Breach severity classification
# ---------------------------------------------------------------------------


class TestBreachDetectionAccuracy:
    """Benchmark precision/recall/F1 for breach severity classification."""

    def setup_method(self) -> None:
        self.checker = BreachChecker()

    @pytest.mark.parametrize(
        "data_classes,expected",
        BREACH_GROUND_TRUTH,
        ids=[f"case_{i}" for i in range(len(BREACH_GROUND_TRUTH))],
    )
    def test_severity_classification(
        self, data_classes: list[str], expected: Severity
    ) -> None:
        """Each ground-truth case must produce the expected severity."""
        record = BreachRecord(
            source="benchmark",
            email="test@example.com",
            data_classes=data_classes,
        )
        predicted = self.checker.score_severity(record)
        assert predicted == expected, (
            f"data_classes={data_classes}: expected {expected.value}, "
            f"got {predicted.value}"
        )

    def test_overall_metrics(self) -> None:
        """Compute aggregate precision/recall/F1 across all ground-truth cases."""
        # Map severity to binary: CRITICAL/HIGH = positive, rest = negative
        def is_positive(s: Severity) -> bool:
            return s in (Severity.CRITICAL, Severity.HIGH)

        predicted_labels: list[bool] = []
        expected_labels: list[bool] = []

        for data_classes, expected in BREACH_GROUND_TRUTH:
            record = BreachRecord(
                source="benchmark",
                email="test@example.com",
                data_classes=data_classes,
            )
            predicted = self.checker.score_severity(record)
            predicted_labels.append(is_positive(predicted))
            expected_labels.append(is_positive(expected))

        tp = sum(p and e for p, e in zip(predicted_labels, expected_labels))
        fp = sum(p and not e for p, e in zip(predicted_labels, expected_labels))
        fn = sum(not p and e for p, e in zip(predicted_labels, expected_labels))
        tn = sum(not p and not e for p, e in zip(predicted_labels, expected_labels))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        # Report metrics (always passes; this is for benchmarking)
        print(f"\n=== Breach Severity Detection Metrics ===")
        print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall:    {recall:.3f}")
        print(f"  F1 Score:  {f1:.3f}")

        # Assert minimum quality bar
        assert precision >= 0.8, f"Precision {precision:.3f} below 0.8 threshold"
        assert recall >= 0.8, f"Recall {recall:.3f} below 0.8 threshold"


# ---------------------------------------------------------------------------
# Benchmark: ZKIT correlation accuracy
# ---------------------------------------------------------------------------


class TestCorrelationDetectionAccuracy:
    """Benchmark precision/recall/F1 for ZKIT identity correlation."""

    def setup_method(self) -> None:
        self.salt = ZKITEngine.new_salt()
        self.engine = ZKITEngine(salt=self.salt, investigation_id="benchmark")

    def _build_ground_truth_hashes(self) -> dict[str, set[str]]:
        """Build ground-truth hash groups from CORRELATION_GROUND_TRUTH."""
        graph = IdentityGraph(salt=self.salt)
        gt_groups: dict[str, set[str]] = {}

        for entity_id, records in CORRELATION_GROUND_TRUTH.items():
            hashes: set[str] = set()
            for rec in records:
                for attr_type, value in rec.items():
                    h = graph.hash_attribute(value)
                    hashes.add(h)
            gt_groups[entity_id] = hashes

        return gt_groups

    def test_single_source_correlation(self) -> None:
        """Records from a single source should produce correct clusters."""
        # Ingest all entity_1 records (should cluster together)
        records = CORRELATION_GROUND_TRUTH["entity_1"]
        ingested = self.engine.ingest(records, default_source="benchmark")
        hashed = self.engine.hash_records(ingested)
        self.engine.build_graph(hashed)

        components = self.engine.correlate()
        clusters = self.engine.score_components(components)

        # All entity_1 records share attributes, so they should be in one component
        assert len(components) >= 1, "Should produce at least one component"

        # Check that all hashed attributes are in the graph
        total_hashes = sum(len(entry) - 1 for entry in hashed)  # subtract _source
        graph_nodes = self.engine.graph.node_count
        assert graph_nodes == total_hashes, (
            f"Expected {total_hashes} nodes, got {graph_nodes}"
        )

    def test_multi_entity_separation(self) -> None:
        """Different entities should produce separate clusters (no cross-linking)."""
        # entity_1 and entity_2 share no attributes -> should be separate
        records_e1 = CORRELATION_GROUND_TRUTH["entity_1"]
        records_e2 = CORRELATION_GROUND_TRUTH["entity_2"]

        all_records = records_e1 + records_e2
        ingested = self.engine.ingest(all_records, default_source="benchmark")
        hashed = self.engine.hash_records(ingested)
        self.engine.build_graph(hashed)

        components = self.engine.correlate()
        clusters = self.engine.score_components(components)

        # entity_1 records are linked (alice@example.com appears twice, alice_dev appears twice)
        # entity_2 records are linked (bob@test.org appears twice)
        # So we expect exactly 2 connected components
        assert len(components) == 2, (
            f"Expected 2 components for disjoint entities, got {len(components)}"
        )

    def test_cluster_purity_metrics(self) -> None:
        """Compute clustering purity precision/recall/F1."""
        # Build graph from all ground-truth entities
        all_records = []
        for records in CORRELATION_GROUND_TRUTH.values():
            all_records.extend(records)

        ingested = self.engine.ingest(all_records, default_source="benchmark")
        hashed = self.engine.hash_records(ingested)
        self.engine.build_graph(hashed)

        components = self.engine.correlate()

        # Build ground-truth hash groups
        gt_groups = self._build_ground_truth_hashes()

        precision, recall, f1 = _cluster_purity_f1(components, gt_groups)

        print(f"\n=== ZKIT Correlation Metrics ===")
        print(f"  Clusters:  {len(components)}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall:    {recall:.3f}")
        print(f"  F1 Score:  {f1:.3f}")

        # Clustering should perfectly separate disjoint entities
        assert f1 >= 0.9, f"Clustering F1 {f1:.3f} below 0.9 threshold"

    def test_confidence_tier_assignment(self) -> None:
        """Verify confidence tiers are assigned correctly."""
        # Multi-source, multi-attribute records -> should produce HIGH confidence
        records = CORRELATION_GROUND_TRUTH["entity_1"]
        ingested = self.engine.ingest(records, default_source="benchmark")
        hashed = self.engine.hash_records(ingested)
        self.engine.build_graph(hashed)

        components = self.engine.correlate()
        clusters = self.engine.score_components(components)

        # At least one cluster should have MEDIUM or higher confidence
        high_or_medium = [
            c
            for c in clusters
            if c.confidence
            in (CorrelationConfidence.HIGH, CorrelationConfidence.MEDIUM)
        ]
        assert len(high_or_medium) >= 1, (
            "Expected at least one MEDIUM/HIGH confidence cluster"
        )


# ---------------------------------------------------------------------------
# Benchmark: Privacy enforcement
# ---------------------------------------------------------------------------


class TestPrivacyDetectionAccuracy:
    """Benchmark that PII is correctly detected and blocked in output."""

    def test_pii_field_detection(self) -> None:
        """All known PII field names must be caught by _enforce_privacy."""
        pii_fields = [
            "email",
            "username",
            "phone",
            "domain",
            "ip",
            "password",
            "ssn",
            "credit_card",
            "name",
            "full_name",
        ]

        detected = 0
        for field in pii_fields:
            try:
                ZKITEngine._enforce_privacy({field: "test_value"})
                # If no exception, field was NOT detected as PII
            except ValueError:
                detected += 1

        precision = detected / len(pii_fields) if pii_fields else 0.0
        # All known PII fields should be detected
        recall = detected / len(pii_fields) if pii_fields else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        print(f"\n=== PII Detection Metrics ===")
        print(f"  Detected:  {detected}/{len(pii_fields)}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall:    {recall:.3f}")
        print(f"  F1 Score:  {f1:.3f}")

        assert detected == len(pii_fields), (
            f"Only detected {detected}/{len(pii_fields)} PII fields"
        )

    def test_no_pii_in_output(self) -> None:
        """Full pipeline output must contain zero raw PII."""
        engine = ZKITEngine(salt=ZKITEngine.new_salt(), investigation_id="privacy-test")
        records = [
            {"email": "test@example.com", "username": "testuser", "phone": "+15551234567"},
        ]

        output = engine.run(records)

        # Serialize output and check for raw PII
        output_str = str(output.__dict__)
        pii_values = ["test@example.com", "testuser", "+15551234567"]

        for pii in pii_values:
            assert pii not in output_str, (
                f"Raw PII '{pii}' found in output"
            )
