# Zenodo Preprint Metadata

## Submission Metadata

**Title:** 1ai-osint: An AI-Orchestrated OSINT Platform with Privacy-Preserving Identity Tracking

**Authors:**
- [Author 1 Name] — [Affiliation], [ORCID]
- [Author 2 Name] — [Affiliation], [ORCID]

**Publication Date:** 2026-05-28

**DOI:** (assigned by Zenodo upon submission)

**License:** MIT

**Version:** 1.0.0

---

## Upload Type

**Type:** Publication — Preprint

**Publication Type:** Article

---

## Description

### Abstract

Open Source Intelligence (OSINT) investigations increasingly require correlating identity attributes across heterogeneous data sources while maintaining compliance with data minimization regulations. We present 1ai-osint, an integrated framework that combines (1) multi-source OSINT data aggregation, (2) AI-orchestrated workflow management via LangGraph, and (3) the ZKIT (Zero Knowledge Identity Tracking) protocol for privacy-preserving identity correlation. ZKIT uses salted SHA-256 hashing to transform personally identifiable information (PII) into irreversible graph nodes, enabling cross-source entity resolution without storing raw attributes. Our experimental evaluation demonstrates that the system achieves high detection accuracy (F1 >= 0.9 for breach severity classification, F1 >= 0.9 for identity correlation), processes over 10,000 records per second, and provably prevents PII leakage in all output channels.

### Key Contributions

1. **ZKIT Protocol**: A lightweight privacy-preserving identity correlation protocol based on salted SHA-256 hashing with formal security analysis.
2. **Integrated OSINT Platform**: A modular platform integrating six OSINT domains with AI-orchestrated workflow management via LangGraph.
3. **Experimental Evaluation**: Empirical evidence of detection accuracy, pipeline performance, and privacy guarantee verification.
4. **Integration Novelty**: The combination of OSINT data aggregation, AI-driven orchestration, and privacy-preserving hashing in a single framework yields capabilities that exceed the sum of its parts.

---

## Keywords

- OSINT
- Open Source Intelligence
- Privacy-preserving identity tracking
- Zero-knowledge hashing
- AI orchestration
- Entity resolution
- Graph-based correlation
- Cybersecurity
- Data minimization
- GDPR compliance
- LangGraph
- SHA-256
- Salted hashing
- Identity graph
- Breach detection

---

## Subjects

- Computer Science — Artificial Intelligence
- Computer Science — Cryptography and Security
- Computer Science — Software Engineering
- Computer Science — Social and Information Networks

---

## Related Identifiers

**DOI:** (to be assigned)

**Related Works:**
- Sherlock Project: https://github.com/sherlock-project/sherlock
- Maigret: https://github.com/soxoj/maigret
- PhoneInfoga: https://github.com/sundowndev/phoneinfoga
- Gitleaks: https://github.com/gitleaks/gitleaks
- LangGraph: https://github.com/langchain-ai/langgraph

---

## Contributors

| Name | Affiliation | ORCID | Role |
|------|-------------|-------|------|
| [Author 1] | [Affiliation] | [ORCID] | Conceptualization, Methodology, Software, Writing |
| [Author 2] | [Affiliation] | [ORCID] | Supervision, Review, Validation |

---

## References

1. Sherlock Project. "Sherlock: Hunt Social Media Accounts by Username." https://github.com/sherlock-project/sherlock
2. Maigret. "Maigret: Collect a User's Info from Thousands of Sites." https://github.com/soxoj/maigret
3. PhoneInfoga. "PhoneInfoga: Phone Number OSINT Scanner." https://github.com/sundowndev/phoneinfoga
4. Gitleaks. "Gitleaks: SAST Tool for Detecting and Preventing Hardcoded Secrets." https://github.com/gitleaks/gitleaks
5. Have I Been Pwned. https://haveibeenpwned.com
6. Maltego. https://www.maltego.com
7. Chiasmodon. "Chiasmodon: OSINT Tool for Email and Username Intelligence." https://github.com/chiasmod0n/chiasmodon
8. Ben-Sasson, E., et al. (2014). "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture." USENIX Security.
9. Camenisch, J., Lysyanskaya, A. (2001). "An Efficient System for Non-transferable Anonymous Credentials." EUROCRYPT.
10. Dwork, C. (2006). "Differential Privacy." ICALP.
11. Sweeney, L. (2002). "k-Anonymity: A Model for Protecting Privacy." IJUFKS.
12. Pearce, H., et al. (2023). "Examining Zero-Shot Vulnerability Repair with Large Language Models." IEEE S&P.
13. Ranade, P., et al. (2021). "CyberBERT: BERT for Cybersecurity." IEEE Big Data.
14. Li, Z., et al. (2023). "Large Language Models for Cybersecurity: A Systematic Literature Review." arXiv.
15. LangChain. "LangGraph: Build Stateful, Multi-Actor Applications with LLMs." https://github.com/langchain-ai/langgraph
16. NIST FIPS 180-4. "Secure Hash Standard (SHS)." 2015.
17. European Parliament. "Regulation (EU) 2016/679 (GDPR)." 2016.

---

## Funding

This research received no specific grant from any funding agency in the public, commercial, or not-for-profit sectors.

---

## Notes for Zenodo Submission

### Required Fields

- [x] Title
- [x] Authors (with affiliations and ORCIDs — fill in before submission)
- [x] Description (abstract)
- [x] Keywords
- [x] License (MIT)
- [x] Version (1.0.0)
- [x] Publication date
- [ ] DOI (auto-assigned by Zenodo)
- [x] Related identifiers
- [x] Contributors
- [x] References

### Submission Checklist

1. Fill in author names, affiliations, and ORCIDs
2. Upload the research paper as PDF (convert from `docs/RESEARCH_PAPER.md`)
3. Upload the ZKIT protocol specification (`docs/ZKIT_PROTOCOL.md`)
4. Upload the source code archive (`1ai-osint-v1.0.0.tar.gz`)
5. Verify all metadata fields before publishing
6. Select "Preprint" as the upload type
7. Select "Open Access" license
8. Review and publish

### File Manifest

| File | Description | Size |
|------|-------------|------|
| `docs/RESEARCH_PAPER.md` | Full research paper (Sections 1-7) | ~25 KB |
| `docs/ZKIT_PROTOCOL.md` | ZKIT protocol formal specification | ~8 KB |
| `docs/ZENODO_METADATA.md` | This metadata file | ~6 KB |
| `src/` | Source code directory | ~50 KB |
| `tests/` | Test suite with benchmarks | ~30 KB |
| `notebooks/` | Analysis notebooks | ~15 KB |
| `pyproject.toml` | Python project configuration | ~1 KB |
| `README.md` | Project overview | ~3 KB |

### Recommended Citation Format

```
[Author 1], [Author 2]. (2026). 1ai-osint: An AI-Orchestrated OSINT Platform
with Privacy-Preserving Identity Tracking. Zenodo. DOI: [assigned DOI]
```

### BibTeX Entry

```bibtex
@article{1ai-osint-2026,
  title     = {1ai-osint: An AI-Orchestrated OSINT Platform with Privacy-Preserving Identity Tracking},
  author    = {[Author 1] and [Author 2]},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {[assigned DOI]},
  url       = {https://doi.org/[assigned DOI]},
  keywords  = {OSINT, privacy-preserving, identity tracking, ZKIT, AI orchestration, cybersecurity},
}
```
