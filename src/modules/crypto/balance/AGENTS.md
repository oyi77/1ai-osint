<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# balance

## Purpose
Core crypto engine — multi-chain balance checking, address derivation, smart generation, scanning, and automated sweeping of found funds.

## Key Files
| File | Description |
|------|-------------|
| `chains.py` | Chain definitions and configurations (10+ chains) |
| `deriver.py` | Address derivation from mnemonics/keys — has `_COIN_MAP` for chain support |
| `checker.py` | Balance checking logic |
| `multicall.py` | Batch balance checking via multicall |
| `sweeper.py` | Automated fund sweeping to destination wallets |
| `scanner_coordinator.py` | Orchestrates scanning pipeline |
| `scanner_engine.py` | Core scanning engine |
| `scanner_key.py` | Key-based scanning |
| `scanner_dork.py` | Google dork-based scanning |
| `scanner_github.py` | GitHub leak scanning |
| `scanner_paste.py` | Paste site scanning |
| `scanner_telegram.py` | Telegram channel scanning |
| `smart_generator.py` | Smart key generation with hit pattern feedback |
| `bloom.py` | Bloom filter for deduplication |
| `hit_logger.py` | Logs successful finds |
| `ai_analyzer.py` | AI-powered analysis of findings |
| `targeted_search.py` | Targeted search operations |
| `leak_scanner.py` | Leak-specific scanning |
| `leak_scanner_telegram.py` | Telegram leak scanner |
| `_leak_shared.py` | Shared leak scanning utilities |
| `api_rotation.py` | API endpoint rotation with per-chain locks |
| `provider_profiles.py` | RPC provider configurations |
| `tool.py` | CLI tool interface |

## For AI Agents

### Working In This Directory
- **Hot path** — this directory gets the most edits
- Adding new chains requires updating `_COIN_MAP` in `deriver.py`
- Program-owned accounts (owner != System Program) should be filtered before sweep
- Sweep: subtract rent-exempt minimum (890880 lamports) for SOL
- Phantom Solana derivation != bip_utils BIP-44 — ask user for private key export
- ERC-20 tokens checked via `eth_call balanceOf()`, not just native balance
- `run_once()` must init sweeper, not just `start()`
- skipPreflight=False + confirm loop for Solana sweeps

### Testing Requirements
- Mock `multicall.batch_check_balances` for EVM, not `check_balance`
- Pass `MagicMock` client with `AsyncMock` post() for ERC-20 tests

### Common Patterns
- Per-chain locks + batching + rotator for API calls
- 5 workers, sync `report_failure` (asyncio.Lock fails in sync __init__)
- Smart generator uses hit pattern feedback + positional frequency biasing

## Dependencies

### Internal
- `src/core/models.py` — Finding, ScanResult models
- `src/config.py` — configuration

### External
- web3.py — EVM interaction
- solders — Solana SDK (0.27.1)
- bit — Bitcoin transactions
- httpx — async HTTP
- python-nacl — signing for Solana

> Last updated: fixed stale `src/models.py` reference → `src/core/models.py` (commit 8fa2bbf)

<!-- MANUAL: -->
