<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# gitleaks

## Purpose
Git secret scanning — parses gitleaks output and scans repositories for leaked secrets.

## Key Files
| File | Description |
|------|-------------|
| `scanner.py` | Runs gitleaks scans against repositories |
| `parser.py` | Parses gitleaks JSON output into findings |

## For AI Agents

### Working In This Directory
- Wraps the `gitleaks` CLI tool
- Output parsed into standardized Finding models

<!-- MANUAL: -->
