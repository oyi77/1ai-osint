# Plan: Crypto Balance Scanner — Full-Stack Wallet Discovery Platform

## Status: pending approval

## Changelog (Architect + Critic improvements applied)
- [x] Benchmark gate: < 100/sec triggers investigation; 100+/sec proceeds with Option A
- [x] API throughput benchmark added to Phase 0
- [x] derive_from_mnemonic must use run_in_executor (CPU-bound PBKDF2)
- [x] Private key stripping before logging (Principle 3 operationalized)
- [x] Error isolation per worker (try/except, continue scanning)
- [x] Graceful shutdown (SIGINT/SIGTERM handling, flush buffered writes)
- [x] CLI: make target optional, add --scan-mode, --workers, --duration options
- [x] check_balance() must plumb client parameter through dispatch
- [x] Hit logger uses standalone async class (not existing synchronous Database)
- [x] Batch inserts every 100 hits in hit_logger
- [x] CoinGecko rate limiting noted (cache prices, respect limits)

## RALPLAN-DR Summary

### Principles
1. **Honest throughput targets** — Free APIs cap at ~10-50 mnemonics/sec; architecture must match reality, not aspirations
2. **Graceful degradation** — API rotation handles failures; partial results better than crashes
3. **Security by design** — Never store private keys; only store addresses + derivation paths
4. **Async-native I/O** — All network calls async with shared connection pools; CPU-bound work offloaded via `run_in_executor`
5. **Minimal dependencies** — Build on existing bip-utils + httpx; add aiosqlite for async DB

### Decision Drivers
1. **API throughput ceiling** — Free APIs are the bottleneck (~10-50 mnemonics/sec), not CPU or local throughput
2. **Zero cost** — Free APIs only; architecture must work within rate limits
3. **Alert latency** — <5 seconds from hit to Telegram notification

### Viable Options

#### Option A: Async Worker Pool with run_in_executor (CHOSEN)
**Approach:** Python `asyncio` with configurable worker count (default: 20). CPU-bound derivation via `run_in_executor(None, ...)`. I/O-bound balance checks via shared `httpx.AsyncClient`. API rotation across multiple free endpoints.

**Pros:**
- Leverages existing httpx async client
- Connection pooling via shared client
- CPU work offloaded to thread pool, doesn't block event loop
- Simple to implement and debug

**Cons:**
- Thread pool still limited by GIL for true CPU parallelism
- Ceiling ~50-200 mnemonics/sec depending on API limits

#### Option B: Multiprocessing + Async
**Approach:** Multiple Python processes (via `multiprocessing.Pool`), each running async workers. CPU-bound derivation in processes, I/O-bound API calls in async.

**Pros:**
- True CPU parallelism for derivation
- Can exceed 1000+/sec if APIs allow

**Cons:**
- Complex inter-process coordination
- Higher memory usage
- Overkill when APIs are the bottleneck

**Why A chosen:** The bottleneck is free API rate limits, not CPU. Even with perfect CPU parallelism, free APIs cap throughput at ~10-50 mnemonics/sec. Option A is simpler and sufficient.

### Decision
**Option A chosen.** Realistic target: 10-50 mnemonics/sec with free APIs (up to 100+ with paid RPC providers in future). Architecture scales to Option B if paid APIs are added.

---

## Phase 0: Foundation Fixes (Prerequisite)

### 0a. Benchmark derivation throughput
**File:** `tests/benchmarks/benchmark_derivation.py`
- Run `derive_from_mnemonic()` with all 5 chains, 100 iterations
- Measure single-thread mnemonics/sec
- **Gate:** If < 100/sec, investigate optimization before continuing

### 0b. Refactor checker.py for shared httpx client
**File:** `src/modules/crypto/balance/checker.py`
- Add optional `client: httpx.AsyncClient` parameter to `check_btc_balance()`, `check_evm_balance()`, `check_sol_balance()`, and `check_balance()` (dispatch function)
- When provided, reuse; when None, create new (backward compatible)
- This enables connection pooling for the scanner

### 0c. Async rate limiter support
**File:** `src/rate_limiter.py`
- Add `async def acquire_async(key, tokens)` using `asyncio.sleep()` instead of `time.sleep()`
- Avoid disk I/O on every call — batch state saves
- Backward compatible: existing sync `wait()` unchanged

### 0d. Fix missing dependencies
**File:** `pyproject.toml`
- Add `eth-account>=0.10.0` (used by `deriver.py:170`)
- Add `aiosqlite>=0.19.0` (for async hit logger)

---

## Phase 1: Infrastructure (Foundation)

**Files:** `src/modules/crypto/balance/api_rotation.py`, `src/modules/crypto/balance/hit_logger.py`

### 1. Create API rotation manager (`api_rotation.py`)
- Round-robin across multiple free endpoints per chain
- Track endpoint health (success/failure counts)
- Auto-disable endpoints that fail 3x consecutively, re-enable after 60s
- Add concrete endpoint inventory:
  - BTC: blockstream.info, mempool.space
  - ETH: eth.llamarpc.com, eth.public-rpc.com, cloudflare-eth.com
  - BSC: bsc-dataseed.binance.org, bsc-dataseed1.binance.org
  - Polygon: polygon-rpc.com, polygon-mainnet.g.alchemy.com (free)
  - SOL: api.mainnet-beta.solana.com, solana-mainnet.g.alchemy.com (free)

### 2. Create hit logger (`hit_logger.py`)
- Standalone async class using `aiosqlite`
- New `wallet_hits` table: address, chain, balance, usd_value, mnemonic_hash, derivation_path, found_at, source
- **Private keys are NEVER stored** — strip `private_key_hex` before logging
- Write buffer: flush every 10 hits or every 5 seconds (whichever comes first)
- Telegram bot alert via httpx POST to `https://api.telegram.org/bot{token}/sendMessage`
- Webhook POST with JSON payload
- Alert format: `🪙 HIT: {chain} | {address} | {balance} {symbol} (~${usd_value})`

### 3. Update config (`src/config.py`)
- Add `telegram_bot_token: Optional[str]`
- Add `telegram_chat_id: Optional[str]`
- Add `webhook_url: Optional[str]`
- Add `scanner_workers: int = 20`
- Add `scanner_mode: str = "targeted"` (default to targeted, not random)

---

## Phase 2: Random Scanner Engine

**Files:** `src/modules/crypto/balance/scanner_engine.py`

### 4. Create scanner engine (`scanner_engine.py`)
- `RandomScanner` class with configurable worker count
- `async run(duration_sec=None, max_mnemonics=None)` — main loop
- Each worker: generate_mnemonic → derive_addresses (via `run_in_executor`) → check_balances (async) → log_hits
- Use `asyncio.Semaphore` to limit concurrent API calls (default: 10)
- Error isolation: try/except per worker, log errors, continue scanning
- Progress reporting: mnemonics/sec, hits found, API errors
- **Graceful shutdown:** Handle SIGINT/SIGTERM, flush pending writes, report final stats

### 5. Performance optimization
- Shared `httpx.AsyncClient` with connection limits (max 20 connections)
- Price caching: module-level `_price_cache: dict` in `checker.py` with 60-second TTL — check timestamp before fetching, reuse cached prices if fresh
- `run_in_executor(None, derive_from_mnemonic)` for CPU-bound derivation
- Connection pooling via httpx.AsyncClient with connection limits

---

## Phase 3: Targeted Search Interface

**Files:** `src/modules/crypto/balance/targeted_search.py`

### 6. Create targeted search (`targeted_search.py`)
- `KnownMnemonicLookup(mnemonic, chains, account_range)` — derive and check specific mnemonic
- `AccountRangeScan(mnemonic, chain, start, end)` — scan accounts 0-N for a seed
- `FilteredRandomScan(chains, min_balance, derivation_paths)` — random scan with filters
- All methods return `ScanResult` with findings

---

## Phase 4: Leak Scanner (Deferred)

**Deferred to future plan.** Reasons:
- Different input sources (web scraping, GitHub API) with different rate limits and ToS constraints
- Google dorking violates Google ToS
- GitHub API rate limit (30 req/min) makes scanning very slow
- Different risk profile (legal liability for credential harvesting)
- Should be its own module (`src/modules/crypto/leak_finder/`), not part of balance scanner

---

## Phase 5: CLI Integration

**Files:** `src/cli.py`

### 7. Extend existing `scan` command (compatible with current typer pattern)
- Make `target` optional with default `"random"` when module is crypto_balance
- **Targeted mode:** `python -m src.cli scan "abandon abandon..." --module crypto_balance`
- **Address mode:** `python -m src.cli scan 0x123... --module crypto_balance`
- **Random mode:** `python -m src.cli scan --module crypto_balance --scan-mode random --workers 20 --duration 3600`
- Add options: `--scan-mode targeted|random`, `--workers 20`, `--duration 3600`, `--account-count`, `--min-balance`
- `check_balance()` in checker.py must plumb `client` parameter through dispatch function
- `target` argument accepts "random" as a special value for random scan mode

---

## Phase 6: Tests

### 8. Unit tests
**Files:** `tests/unit/test_crypto_balance.py` (extend), `tests/unit/test_leak_scanner.py` (deferred)

- API rotation: round-robin, health tracking, auto-disable/re-enable
- Hit logger: aiosqlite persistence, Telegram alert mock, private key stripping
- Scanner engine: worker pool, semaphore limiting, progress reporting, error isolation
- Targeted search: known mnemonic, account range, filtered scan
- End-to-end: targeted scan → hit → log → alert (all mocked APIs)

---

## File Summary

### New files (7):
- `src/modules/crypto/balance/api_rotation.py`
- `src/modules/crypto/balance/scanner_engine.py`
- `src/modules/crypto/balance/targeted_search.py`
- `src/modules/crypto/balance/hit_logger.py`
- `tests/unit/test_crypto_balance.py` (extend existing)
- `tests/benchmarks/benchmark_derivation.py`

### Modified files (5):
- `src/modules/crypto/balance/chains.py` — add multi-endpoint support
- `src/modules/crypto/balance/checker.py` — refactor for shared httpx client
- `src/modules/crypto/balance/__init__.py` — add modes (targeted/random)
- `src/cli.py` — add --scan-mode, --workers, --duration flags
- `src/config.py` — add telegram/webhook settings
- `src/rate_limiter.py` — add async support
- `pyproject.toml` — add eth-account, aiosqlite dependencies

---

## Acceptance Criteria (Testable)
- [ ] `derive_from_mnemonic()` benchmark ≥100 mnemonics/sec single-thread (Phase 0 gate)
- [ ] Shared httpx client used for all balance checks (no per-call client creation)
- [ ] `run_in_executor` used for CPU-bound derivation in scanner engine
- [ ] API rotation cycles through endpoints without repeating until all tried
- [ ] Disabled endpoints re-enable after 60s cooldown
- [ ] Hit logger writes to SQLite `wallet_hits` table with all fields
- [ ] **No private keys stored in SQLite** (verified by test)
- [ ] Hit logger flushes writes in batches (every 10 hits or 5 seconds)
- [ ] Telegram alert POSTs to correct bot endpoint with formatted message
- [ ] Webhook POST fires with JSON payload
- [ ] `KnownMnemonicLookup("abandon abandon...")` returns addresses for all chains
- [ ] `AccountRangeScan(mnemonic, "ethereum", 0, 10)` returns 10 addresses
- [ ] `FilteredRandomScan(chains=["bitcoin"])` only checks BTC
- [ ] Scanner handles SIGINT gracefully (flushes writes, reports stats)
- [ ] All existing 554 tests pass unchanged
- [ ] New tests achieve ≥80% coverage on new modules
- [ ] CLI: `python -m src.cli scan "abandon abandon..." --module crypto_balance` works
- [ ] CLI: `python -m src.cli scan random --module crypto_balance --scan-mode random` works

## Risks and Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Free APIs rate-limit aggressively | Scanner stalls | API rotation + exponential backoff + endpoint health tracking + CoinGecko price caching |
| Telegram bot token leaked in logs | Security | Never log tokens; use env vars only |
| Private keys stored in SQLite | Security violation | Strip `private_key_hex` before logging; add unit test verification |
| SQLite write contention at high throughput | Data loss | aiosqlite + batch writes (every 10 hits or 5 seconds) |
| CPU-bound derivation blocks event loop | Performance | `run_in_executor(None, ...)` for all derivation calls |
| Worker unhandled exception | Scanner crash | try/except per worker, log error, continue scanning |
| CoinGecko rate limiting | Price lookup fails | Cache prices for 60 seconds |

## Verification Steps
1. **Phase 0 benchmark gate:** `python -m pytest tests/benchmarks/benchmark_derivation.py -v` — verify ≥100 mnemonics/sec
2. Run unit tests: `python -m pytest tests/unit/test_crypto_balance.py -v`
3. Run full suite: `python -m pytest tests/ -q` — expect 554+ tests passing
4. Integration: `python -m src.cli scan "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --module crypto_balance` — verify addresses returned
5. Security: `python -m pytest tests/unit/test_crypto_balance.py -k "private_key" -v` — verify no keys in DB

## ADR (Architecture Decision Record)

### Decision
Use Async Worker Pool (Option A) with `run_in_executor` for CPU-bound work; honest throughput target of 10-50 mnemonics/sec with free APIs.

### Drivers
- Free APIs are the bottleneck, not CPU (10-50 req/sec per endpoint)
- Zero budget constraint
- <5 second alert latency requirement
- Must integrate with existing CLI pattern

### Alternatives Considered
- **Option B (Multiprocessing + Async)**: Rejected — overkill when APIs are the bottleneck. Would only help if paid APIs are added.
- **Keep checker.py as-is**: Rejected — connection churn defeats async concurrency benefits
- **Use existing Database class for logging**: Rejected — synchronous, no async support

### Why Chosen
Option A is simpler and sufficient for free API constraints. The real bottleneck is API rate limits, not CPU or local throughput. Architecture scales to Option B if paid APIs are added later.

### Consequences
- Phase 0 adds ~1 day but eliminates the risk of building on incorrect assumptions
- checker.py refactor requires updating existing tests (backward compatible change)
- aiosqlite adds a new dependency (lightweight, well-maintained)
- Leak scanner deferred to separate plan/module

### Follow-ups
- [ ] Run derivation benchmark before starting Phase 1
- [ ] If benchmark < 100/sec, investigate optimization
- [ ] Add `eth-account` and `aiosqlite` to pyproject.toml
- [ ] Refactor checker.py to accept shared httpx client
- [ ] Future: leak scanner as separate module
- [ ] Future: paid RPC provider support for 1000+/sec
