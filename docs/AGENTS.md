<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 -->

# docs

## Purpose
Research documentation, protocol specifications, and benchmark results for the OSINT toolkit.

## Key Files
| File | Description |
|------|-------------|
| `index.md` | mkdocs landing page (site root of `site/`) |
| `architecture.md` | System architecture |
| `1ai-osint-Blueprint.md` | Product blueprint |
| `blueprint-gap-analysis.md` | Blueprint gap analysis |
| `roadmap.md` / `ROADMAP.md` | Improvement plans (duplicated content — update both) |
| `VERIFIED.md` | Verification status / evidence ledger (self-superseding) |
| `cli.md` | CLI usage docs |
| `configuration.md` | Configuration reference |
| `modules.md` | Module catalog |
| `development.md` | Dev workflow |
| `getting-started.md` | Quick start |
| `web-ui.md` | Web UI docs |
| `compliance.md` | Compliance notes |
| `agentic.md` | Agentic workflows |
| `references.md` | External references |
| `BENCHMARK.md` | Benchmark methodology |
| `BENCHMARK_RESULTS.md` | Performance benchmark results |
| `RESEARCH.md` | Core research findings |
| `RESEARCH_PAPER.md` | Formal research paper |
| `SDD.md` | Software Design Document |
| `ZKIT_PROTOCOL.md` | ZKIT protocol specification |
| `ZENODO_METADATA.md` | Zenodo publication metadata |
| `syntax-check-fallback.md` | Syntax checking fallback documentation |
| `evidence/` | Generated evidence artifacts (soak, benchmark, agent-vs-batch, live source probes, security) |

## For AI Agents

### Working In This Directory
- Documentation is markdown-based (mkdocs-material site — see `mkdocs.yml`; build/serve with `uv run mkdocs build` / `uv run mkdocs serve`, output in `site/`)
- Update timestamps when modifying docs
- Cross-reference with `PLAN.md` at project root for architecture alignment
- `roadmap.md` and `ROADMAP.md` duplicate each other — update both

<!-- MANUAL: -->
> Last updated: expanded key files, added mkdocs/evidence notes (commit 8fa2bbf)
