<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 -->

# fixtures

## Purpose
Shared test data and mock API responses for unit tests.

## Key Files
| File | Description |
|------|-------------|
| `mock_api_responses.py` | Mock HTTP responses for external API calls |
| `sample_secrets.json` | Sample leaked secrets for testing |
| `test_identities.json` | Sample identity data for correlation tests |

## For AI Agents

### Working In This Directory
- Add new mock responses here when testing new API integrations
- Keep fixtures minimal — only include data needed for specific test cases
- `tests/conftest.py` exposes `sample_secrets.json` / `test_identities.json` via the `sample_secrets_path` / `sample_identities_path` fixtures

<!-- MANUAL: -->
> Last updated: documented conftest sample_secrets_path/sample_identities_path fixtures (commit 8fa2bbf)
