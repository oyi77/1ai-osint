---
scope: gitleaks
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# gitleaks

> Last updated: remove non-existent parser.py, correct GitHound docstring, document severity mapping (commit 8fa2bbf)

## Purpose
Git secret scanning — runs the `gitleaks` CLI against repositories and parses findings.

## Key Files
| File | Description |
|------|-------------|
| `scanner.py` | `GitleaksModule` (line 31) — runs `gitleaks detect --source ... --format json --no-banner --no-color` (exit codes 0/1 = OK), parses JSON or line-delimited output; `_SEVERITY_MAP` (line 13) |
| `__init__.py` | Exports `GitleaksModule` |

## For AI Agents

### Working In This Directory
- Wraps the `gitleaks` CLI (requires it on PATH or pass `gitleaks_path`); exit codes 0/1 are treated as success, anything else as scan failure
- Findings: confidence 0.9, match truncated to 100 chars, tags `[secret, gitleaks, rule_id]`
- `_SEVERITY_MAP`: CRITICAL — aws-access-token, aws-secret-key, github-token, gitlab-token, private-key; HIGH — generic-api-key, generic-password, slack-token, stripe-access-token; MEDIUM — google, heroku, mailgun, sendgrid, twilio-api-key
- `analyze()` gives severity/rule breakdown; `learn()` is a no-op
- Note: the module docstring used to say "GitHound" — it now correctly reads "Secret scanning module using the gitleaks CLI subprocess" (`scanner.py:1`); the actual backend is `gitleaks` (no parser.py exists; parsing lives in scanner.py)

## Dependencies

### External
- `gitleaks` CLI

### Internal
- `src/core/` — models

<!-- MANUAL: -->
> Last updated: fix pass — gitleaks module docstring corrected (scanner.py:1), no longer mentions GitHound
