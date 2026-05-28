# 1ai-osint Performance Benchmark Results

**Date:** 2026-05-28
**Platform:** Darwin (macOS) arm64
**Python:** 3.12.10
**Hash Algorithm:** SHA-256
**Graph Engine:** In-memory Pydantic models

---

## Hash Throughput

| Metric | Value |
|--------|-------|
| Iterations | 10,000 |
| Total time | 0.0053s |
| Per hash | 533ns |
| Throughput | 1,876,187 hashes/sec |

### Batch Ingestion

| Records | Time (s) | Throughput (records/sec) |
|---------|----------|--------------------------|
| 100 | 0.0003 | 294,876 |
| 1,000 | 0.0045 | 223,428 |
| 10,000 | 0.0617 | 161,974 |

---

## Graph Construction Performance

| Records | Time (s) | Nodes | Edges | ms/record |
|---------|----------|-------|-------|-----------|
| 100 | 0.0194 | 305 | 600 | 0.19 |
| 500 | 0.0217 | 1,505 | 3,000 | 0.04 |
| 1,000 | 0.0644 | 3,005 | 6,000 | 0.06 |
| 5,000 | 0.5405 | 15,005 | 30,000 | 0.11 |

### Correlation (Connected Components)

| Metric | Value |
|--------|-------|
| Nodes | 1,050 |
| Edges | 1,500 |
| Components | 50 |
| Time | 0.0019s |

### Cluster Scoring

| Metric | Value |
|--------|-------|
| Components | 20 |
| Clusters | 20 |
| Time | 0.0010s |

---

## Memory Usage

| Metric | Value |
|--------|-------|
| Records | 5,000 |
| Nodes | 15,005 |
| Edges | 30,000 |
| Memory delta | 111.02 MB |
| Per node | 7,758 bytes |
| Serialized node | 219 bytes |
| Projected 100K nodes | 20.9 MB |

**Status: FAILED** -- Memory usage 111.02 MB exceeds the 100 MB limit. This is due to Pydantic model overhead in the in-memory graph. The serialized per-node size is only 219 bytes.

---

## End-to-End Pipeline Throughput

| Records | Time (s) | Clusters | Throughput (records/sec) |
|---------|----------|----------|--------------------------|
| 100 | 0.0053 | 5 | 18,735 |
| 500 | 0.0259 | 5 | 19,334 |
| 1,000 | 0.0547 | 5 | 18,296 |

### Graph Merge

| Metric | Value |
|--------|-------|
| Graph 1 nodes | 500 |
| Graph 2 nodes | 500 |
| New entities | 0 |
| Merged nodes | 1,505 |
| Merge time | 0.0203s |

---

## Detection Benchmarks

### Breach Severity Classification

11 ground-truth cases tested. 7 passed, 4 failed.

**Passed cases:**
- case_0: `["password", "credit card", "email"]` -> CRITICAL
- case_1: `["password", "bank account", "ssn"]` -> CRITICAL
- case_2: `["password_hash", "credit cards", "phone", "address", "dob"]` -> CRITICAL
- case_3: `["password", "email", "username"]` -> HIGH
- case_4: `["credit card", "email"]` -> HIGH
- case_5: `["password_hash", "email", "phone"]` -> HIGH
- case_11: `[]` -> INFO

**Failed cases (severity mismatch):**

| Case | Data Classes | Expected | Actual |
|------|-------------|----------|--------|
| case_7 | `["phone", "physical address"]` | MEDIUM | HIGH |
| case_8 | `["email", "ip addresses"]` | LOW | MEDIUM |
| case_9 | `["email", "username"]` | LOW | MEDIUM |
| case_10 | `["gender"]` | INFO | LOW |

The `BreachChecker.score_severity` method assigns higher severity than the benchmark ground truth expects for lower-sensitivity data classes.

**Overall Breach Metrics (binary: CRITICAL/HIGH = positive):** Precision >= 0.8, Recall >= 0.8 (threshold met).

### ZKIT Correlation Accuracy

| Test | Result |
|------|--------|
| Single source correlation | FAILED (expected 6 nodes, got 4) |
| Multi entity separation | PASSED (2 components) |
| Cluster purity metrics | PASSED (F1 >= 0.9) |
| Confidence tier assignment | PASSED |

### Privacy Detection

| Test | Result |
|------|--------|
| PII field detection | PASSED (10/10 fields) |
| No PII in output | PASSED |

**Detection Results: 14 passed, 5 failed**

---

## Summary

| Benchmark | Result |
|-----------|--------|
| Hash throughput | PASS (1.88M hashes/sec) |
| Batch ingestion | PASS (162K-295K records/sec) |
| Graph construction | PASS |
| Correlation | PASS (0.0019s for 1050 nodes) |
| Scoring | PASS (0.0010s for 20 clusters) |
| Memory footprint | **FAIL** (111 MB > 100 MB limit) |
| Per-node memory | PASS |
| Pipeline (100 rec) | PASS (18.7K records/sec) |
| Pipeline (500 rec) | PASS (19.3K records/sec) |
| Pipeline (1000 rec) | PASS (18.3K records/sec) |
| Graph merge | PASS (0.020s) |
| Breach severity classification | **FAIL** (4/11 cases severity mismatch) |
| Overall breach metrics | PASS (precision/recall >= 0.8) |
| ZKIT correlation | **FAIL** (node count mismatch) |
| ZKIT multi-entity separation | PASS |
| ZKIT cluster purity | PASS (F1 >= 0.9) |
| Privacy PII detection | PASS |
| Privacy output safety | PASS |

**Performance: 11 passed, 1 failed**
**Detection: 14 passed, 5 failed**
**Overall: 25 passed, 6 failed**

---

## Latest Run (2026-05-28 re-run)

### Updated Performance Numbers

| Benchmark | Previous | Latest |
|-----------|----------|--------|
| Hash throughput | 1.88M/sec | 1.35M/sec |
| Batch (100) | 294K/sec | 109K/sec |
| Batch (1K) | 223K/sec | 111K/sec |
| Batch (10K) | 162K/sec | 112K/sec |
| Graph (100) | 0.19ms/rec | 0.28ms/rec |
| Graph (500) | 0.04ms/rec | 0.07ms/rec |
| Graph (1K) | 0.06ms/rec | 0.09ms/rec |
| Graph (5K) | 0.11ms/rec | 0.11ms/rec |
| Pipeline (100) | 18.7K/sec | 7.6K/sec |
| Pipeline (500) | 19.3K/sec | 7.8K/sec |
| Pipeline (1K) | 18.3K/sec | 6.0K/sec |
| Memory (5K) | 111.02 MB | 111.02 MB |

### Breach Detection Metrics (re-run)

| Metric | Value |
|--------|-------|
| TP | 6 |
| FP | 1 |
| FN | 0 |
| TN | 5 |
| Precision | 0.857 |
| Recall | 1.000 |
| F1 Score | 0.923 |

### ZKIT Correlation Metrics (re-run)

| Metric | Value |
|--------|-------|
| Clusters | 3 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 Score | 1.000 |

### Crypto Module Coverage (re-run)

| Module | Coverage |
|--------|----------|
| privatekey/scanner.py | 96% |
| privatekey/checker.py | 86% |
| passphrase/checker.py | 92% |
| passphrase/generator.py | 88% |

---

## Latest Run (2026-05-28 final verification)

### Performance Benchmark (final)

| Metric | Value |
|--------|-------|
| Hash throughput | 1,185,976 hashes/sec (843ns/hash) |
| Batch 100 | 97,939 records/sec |
| Batch 1,000 | 94,363 records/sec |
| Batch 10,000 | 86,529 records/sec |

### Graph Construction (final)

| Records | Time (s) | Nodes | Edges | ms/record |
|---------|----------|-------|-------|-----------|
| 100 | 0.0131 | 305 | 600 | 0.13 |
| 500 | 0.1023 | 1,505 | 3,000 | 0.20 |
| 1,000 | 0.1306 | 3,005 | 6,000 | 0.13 |
| 5,000 | 0.8328 | 15,005 | 30,000 | 0.17 |

### Correlation and Scoring (final)

| Metric | Value |
|--------|-------|
| Correlation (1,050 nodes) | 0.0080s |
| Scoring (20 components) | 0.0054s |
| Pipeline 100 records | 2,125 records/sec (0.047s) |
| Pipeline 500 records | 6,815 records/sec (0.073s) |
| Pipeline 1,000 records | 8,762 records/sec (0.114s) |
| Graph merge | 0.0365s |
| Memory (5,000 records) | 111.02 MB (FAIL: exceeds 100 MB limit) |

### Detection Benchmark (final)

**Overall: 14 passed, 5 failed**

Breach severity classification: 7/11 passed (4 cases have severity mismatch).
Breach overall metrics: Precision=0.857, Recall=1.000, F1=0.923.

ZKIT correlation: Multi-entity separation PASS, Cluster purity F1=1.000, Confidence tiers PASS.
Single-source correlation: FAIL (expected 6 nodes, got 4 -- deduplication of shared attributes).

Privacy: PII detection 10/10 PASS, No PII in output PASS.

### Crypto Module Coverage (final)

| Module | Lines | Covered | Coverage |
|--------|-------|---------|----------|
| privatekey/scanner.py | 105 | 101 | 96% |
| privatekey/checker.py | 116 | 100 | 86% |
| passphrase/checker.py | 89 | 89 | 100% |
| passphrase/generator.py | 41 | 36 | 88% |
| **Combined crypto** | **351** | **326** | **93%** |
