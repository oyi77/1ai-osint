# Autoresearch Mission: Best OSINT Tool

## Mission
Turn 1ai-osint into the best OSINT tool — full identity resolution (any identifier → full graph), 50+ data sources, autonomous sweep pipeline, Docker deployment.

## Spec
See: `.omc/specs/deep-interview-best-osint.md`

## Evaluator
Command: `bash .omc/scripts/best-osint-evaluator.sh`
Criteria: ruff lint clean + 991+ tests passing + 80%+ coverage

## Current State
- 11 shared leak sources + chiasmodon bridge (12 more)
- 9 modules: sources, crypto, data_leaks, gitleaks, identity_tracking, output, people_finder, phone_finder, vuln_scanner
- PyPI-ready CLI with typer
- 991 tests, 80.82% coverage, ruff clean

## Target State
- 50+ data sources
- Full identity resolution: any identifier → complete graph
- Autonomous sweep pipeline
- Docker Compose deployment
- Distributed-ready architecture

## Max Runtime
2 hours from start
