<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# unit

## Purpose
Unit tests mirroring the `src/` module structure. Each test file covers a specific module or component.

## Key Files
| File | Description |
|------|-------------|
| `test_crypto_balance.py` | Crypto balance checker tests (most-run test file) |
| `test_leak_finder.py` | Leak finder coordinator tests |
| `test_coordinator_bloom_generator.py` | Bloom filter + smart generator tests |
| `test_crypto_balance_scanner.py` | Scanner engine tests |
| `test_leak_scanner.py` | Leak scanner tests |
| `test_leak_extractor.py` | Key/entity extraction tests |
| `test_correlation_engine.py` | AI correlation engine tests |
| `test_entity_extractor.py` | Entity extraction tests |
| `test_risk_scorer.py` | Risk scoring tests |
| `test_ai_analyzer.py` | AI analyzer tests |
| `test_cli.py` | CLI argument parsing tests |
| `test_config.py` | Configuration tests |
| `test_database.py` | Database tests |
| `test_models.py` | Pydantic model tests |
| `test_cache.py` | Caching layer tests |
| `test_rate_limiter.py` | Rate limiter tests |
| `test_data_leaks.py` | Data leaks module tests |
| `test_data_leaks_extra.py` | Additional data leaks tests |
| `test_gitleaks.py` | Git secret scanning tests |
| `test_identity_graph.py` | Identity graph tests |
| `test_correlation.py` | Identity correlation tests |
| `test_zkit_engine.py` | ZKIT engine tests |
| `test_zkit_formatter.py` | ZKIT formatter tests |
| `test_report_generator.py` | Report generation tests |
| `test_omniroute_client.py` | LLM client tests |
| `test_orchestrator.py` | AI orchestrator tests |
| `test_people_finder.py` | People finder tests |
| `test_people_finder_tool.py` | People finder tool tests |
| `test_phone_finder.py` | Phone finder tests |
| `test_phone_finder_tool.py` | Phone finder tool tests |
| `test_targeted_search.py` | Targeted search tests |
| `test_crypto_passphrase.py` | Passphrase tests |
| `test_crypto_privatekey.py` | Private key tests |
| `test_vuln_scanner.py` | Vulnerability scanner tests |

## For AI Agents

### Working In This Directory
- **Most-edited test files**: `test_crypto_balance.py` (93x), `test_leak_finder.py`
- Always `rm -f .coverage` before full pytest runs
- Patch source module for locally-imported functions, not calling module
- For EVM: mock `multicall.batch_check_balances`, not `check_balance`
- Always provide `id`/`scan_id` on Finding/ScanResult in test fixtures
- Grep for existing test class names before adding new ones — avoid shadowing
- Mock ERC-20 tests: pass `MagicMock` client with `AsyncMock` post(), don't patch httpx globally

### Testing Requirements
- `pytest tests/unit/` — run all unit tests
- Tests must be independent and idempotent
- Mock all external API calls

<!-- MANUAL: -->
