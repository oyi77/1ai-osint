<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# data_leaks

## Purpose
Data breach and leak aggregation — checks credentials and emails against known breach databases.

## Key Files
| File | Description |
|------|-------------|
| `aggregator.py` | Aggregates results from multiple breach sources |
| `breach_checker.py` | Checks if emails/credentials appear in known breaches |

## For AI Agents

### Working In This Directory
- Integrates with vendor sources under `src/vendor/chiasmodon/`
- Tests in `tests/unit/test_data_leaks.py` and `test_data_leaks_extra.py`

<!-- MANUAL: -->
