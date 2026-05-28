# ZKIT Protocol Specification

**Zero Knowledge Identity Tracking — Formal Protocol Definition**

Version: 1.0.0  
Status: Draft  
Last Updated: 2026-05-28

---

## 1. Overview

ZKIT (Zero Knowledge Identity Tracking) is a lightweight, privacy-preserving protocol for correlating identity attributes across OSINT data sources without storing raw personally identifiable information (PII). The system name "ZKIT" refers to the design goal of zero knowledge *retention* — raw attribute values are never persisted, only their salted cryptographic hashes.

ZKIT is designed for security researchers, red-teamers, and OSINT practitioners who need to correlate entities across platforms while maintaining compliance with data minimization principles (GDPR Art. 5(1)(c)).

---

## 2. Formal Protocol Notation

### 2.1 Definitions

Let the following be defined:

- `S` — a per-investigation salt (secret, randomly generated, 256-bit minimum)
- `attr` — a raw identity attribute (email address, username, phone number, domain)
- `H(x)` — the SHA-256 hash function, producing a 256-bit digest
- `‖` — string concatenation operator

### 2.2 Hash Construction

The ZKIT hash for an attribute is computed as:

```
ZKIT_hash(attr, S) = H( S ‖ ":" ‖ attr )
```

In implementation:

```python
preimage = f"{salt}:{attribute}".encode("utf-8")
zkit_hash = hashlib.sha256(preimage).hexdigest()
```

The hash is a 64-character lowercase hexadecimal string.

### 2.3 Identity Graph

An identity graph `G = (V, E)` is defined as:

- **V** — a set of vertices, where each vertex `v ∈ V` is a ZKIT hash of an identity attribute. Each vertex carries a type label `τ(v) ∈ {email_hash, username_hash, phone_hash, domain_hash}`.
- **E** — a set of undirected edges, where `(u, v) ∈ E` if and only if attributes `u` and `v` were observed co-occurring in the same data source during the same investigation.

Each edge `(u, v)` carries:
- `weight(u, v) ∈ [0.0, 1.0]` — confidence score for the co-occurrence
- `co_occurrences(u, v) ∈ ℕ+` — count of independent observations

### 2.4 Graph Merge

Given two graphs `G₁ = (V₁, E₁)` and `G₂ = (V₂, E₂)` with identical salt `S`:

```
G_merged = (V₁ ∪ V₂, E₁ ∪ E₂)
```

For overlapping vertices/edges, attributes are merged:
- `first_seen = min(first_seen₁, first_seen₂)`
- `last_seen = max(last_seen₁, last_seen₂)`
- `sources = sources₁ ∪ sources₂`
- `co_occurrences = co_occurrences₁ + co_occurrences₂`

---

## 3. Threat Model

### 3.1 Assets Protected

| Asset | Protection Mechanism |
|---|---|
| Raw PII (emails, phones, usernames) | Never stored; only salted hashes persisted |
| Investigation salt `S` | Stored separately from hash data; per-investigation |
| Correlation structure | Revealed only to holders of `S` |

### 3.2 Adversary Model

| Adversary | Capability | ZKIT Defense |
|---|---|---|
| **Passive database attacker** | Gains read access to stored graph data | Cannot reverse hashes without `S`; sees only hash topology |
| **Rainbow table attacker** | Pre-computes hashes for common attributes | Per-investigation salt defeats precomputation; attacker must obtain `S` first |
| **Insider without salt** | Has access to graph data but not the salt | Same as passive attacker — hashes are irreversibly opaque |
| **Insider with salt** | Has both graph data and the salt | Can reverse hashes for that investigation only; scope limited to `S` |
| **Cross-investigation correlator** | Attempts to link graphs across investigations | Different salts produce different hashes for the same attribute; no cross-linking possible |

### 3.3 Trust Boundaries

1. **Salt storage**: The salt `S` MUST be stored in a separate trust domain from the graph data. Compromise of the graph store alone does not reveal raw attributes.
2. **Runtime**: During active investigation, raw attributes exist in memory. The protocol guarantees zero *persistence* of raw PII, not zero *exposure* during runtime.
3. **Transport**: Hashes are transmitted over encrypted channels (TLS 1.3+). The protocol does not define its own transport encryption.

---

## 4. Security Analysis

### 4.1 Preimage Resistance

SHA-256 provides 128-bit preimage resistance. Given a ZKIT hash `h`, an adversary without the salt must solve:

```
find attr such that H(S ‖ ":" ‖ attr) = h
```

This requires brute-forcing the attribute space, which is computationally infeasible for sufficiently complex attributes (entropy > 40 bits).

### 4.2 Salt Entropy Requirements

The salt `S` MUST be:
- At least 256 bits of cryptographic randomness
- Unique per investigation
- Generated using a CSPRNG (e.g., `secrets.token_hex(32)`)

A weak or reused salt reduces ZKIT to unsalted SHA-256, which is vulnerable to rainbow table attacks for low-entropy attributes (e.g., common usernames, short phone numbers).

### 4.3 Hash Collision Resistance

SHA-256 provides 128-bit collision resistance. The probability of accidental collision between two distinct attributes across `n` hashes is approximately:

```
P(collision) ≈ n² / 2^129
```

For practical graph sizes (n < 10^6), this probability is negligible (< 2^-100).

### 4.4 Limitations

1. **Not a zero-knowledge proof**: ZKIT does not use zk-SNARKs, zk-STARKs, or any cryptographic zero-knowledge proof system. The name refers to the design principle of zero knowledge *retention*.
2. **Runtime exposure**: Raw attributes exist in memory during processing. A memory dump during an active investigation would reveal PII.
3. **Salt compromise**: If the salt is compromised, all hashes in that investigation can be reversed via dictionary attack against the attribute space.
4. **Graph topology**: Even without reversing hashes, the graph structure (degree distribution, connected components) reveals statistical information about the underlying identity network.

---

## 5. Privacy Guarantees

### 5.1 Data Minimization

ZKIT satisfies GDPR Article 5(1)(c) — data minimization — by:
- Never persisting raw attribute values
- Storing only irreversible (without salt) hash digests
- Supporting per-investigation salt rotation to limit blast radius

### 5.2 Purpose Limitation

Each salt is scoped to a single investigation. Hashes from one investigation cannot be repurposed or correlated with another investigation's data without re-hashing with the target investigation's salt.

### 5.3 Storage Limitation

Graph data can be safely retained after an investigation by destroying the salt. Without the salt, the graph becomes an opaque topology of meaningless hash identifiers.

### 5.4 Right to Erasure

Destroying the salt `S` effectively renders all stored hashes irreversible, satisfying the spirit of GDPR Article 17 (right to erasure) for the attribute values, even if the hash topology is retained for statistical analysis.

---

## 6. Comparison with Related Approaches

### 6.1 k-Anonymity

| Property | k-Anonymity | ZKIT |
|---|---|---|
| **Mechanism** | Suppress/make attributes so each record is indistinguishable from k-1 others | Hash attributes with salted SHA-256 |
| **Reversibility** | Suppressed values are lost | Reversible with salt (by design) |
| **Correlation** | Limited — records grouped into equivalence classes | Full graph-based correlation via shared hashes |
| **Vulnerability** | Homogeneity attack, background knowledge attack | Salt compromise, rainbow tables (mitigated by salt) |
| **Use case** | Publishing anonymized datasets | Internal investigative correlation |
| **Granularity** | Per-record | Per-attribute (fine-grained) |

**Analysis**: k-Anonymity is designed for *publishing* data to third parties. ZKIT is designed for *internal investigation* where the investigator controls the salt. k-Anonymity provides stronger guarantees for data publication but cannot support the graph-based correlation that ZKIT enables.

### 6.2 Differential Privacy

| Property | Differential Privacy | ZKIT |
|---|---|---|
| **Mechanism** | Add calibrated noise to query results | Deterministic salted hashing |
| **Guarantee** | Formal ε-differential privacy | Computational (SHA-256 hardness) |
| **Utility** | Degraded by noise budget | Full fidelity — no information loss |
| **Reversibility** | Not applicable (noise is irreversible) | Reversible with salt |
| **Composition** | Privacy budget degrades with queries | No composition concern — each hash is independent |
| **Use case** | Statistical queries over sensitive data | Identity correlation in investigations |

**Analysis**: Differential privacy provides a formal mathematical guarantee that any individual's data has bounded influence on query outputs. ZKIT does not provide this guarantee — it instead provides *computational privacy* (hash irreversibility without salt). The approaches solve different problems: differential privacy for statistical disclosure control, ZKIT for operational PII minimization.

### 6.3 Comparison Summary

| Criterion | k-Anonymity | Differential Privacy | ZKIT |
|---|---|---|---|
| **Privacy model** | Suppression + generalization | Noise addition | Salted hashing |
| **Formal guarantee** | Indistinguishability in k-group | ε-differential privacy | SHA-256 preimage resistance |
| **Correlation support** | Weak (equivalence classes only) | None (queries only) | Strong (full graph) |
| **PII in storage** | Suppressed or generalized | Perturbed | Never stored |
| **Utility preservation** | Moderate | Low-moderate | High |
| **Reversibility** | N/A (data suppressed) | N/A (data noisy) | With salt only |
| **Best suited for** | Data publication | Statistical analysis | Investigative OSINT |

---

## 7. Implementation Notes

### 7.1 Supported Attribute Types

| Type | Label | Example Input | Notes |
|---|---|---|---|
| Email | `email_hash` | `user@example.com` | Case-normalized to lowercase before hashing |
| Username | `username_hash` | `alice_dev` | Platform-specific normalization may apply |
| Phone | `phone_hash` | `+15551234567` | E.164 format recommended |
| Domain | `domain_hash` | `example.com` | Lowercase, no protocol prefix |

### 7.2 Salt Lifecycle

```
Investigation Start
    │
    ├─► Generate salt: S = secrets.token_hex(32)
    ├─► Store salt in secure key management
    │
    Investigation Active
    │   ├─► All attribute hashing uses S
    │   └─► Graph operations use S-derived hashes
    │
    Investigation End
    │
    ├─► Option A: Retain salt (graph remains reversible for follow-up)
    └─► Option B: Destroy salt (graph becomes opaque topology)
```

### 7.3 Graph Merging Constraints

Two graphs can only be merged if they share the same salt. Merging graphs with different salts requires re-hashing all attributes from one graph using the other's salt, which requires access to the raw attribute values.

---

## 8. References

1. NIST FIPS 180-4 — Secure Hash Standard (SHA-256)
2. GDPR Article 5 — Principles relating to processing of personal data
3. Sweeney, L. (2002). "k-Anonymity: A Model for Protecting Privacy"
4. Dwork, C. (2006). "Differential Privacy"
5. 1ai-osint Project — Software Design Document (`docs/SDD.md`)
