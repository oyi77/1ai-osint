# Plan: Scanner 100+/sec Optimization

## Status: pending approval

## Current State (Already Done)
- ✅ API concurrency raised to 50 (scanner_engine.py:63)
- ✅ BTC delay reduced to 0.15s (scanner_engine.py:305)
- ✅ 4 BTC endpoints in registry (mempool.space, blockstream.info, blockchain.info, blockcypher)
- ✅ 3 ETH endpoints (ankr, publicnode, 1rpc)
- ✅ 4 BSC endpoints (binance x2, ankr, publicnode)
- ✅ 3 Polygon endpoints (ankr, publicnode, 1rpc)
- ✅ 3 SOL endpoints (mainnet-beta, alchemy/demo, ankr)
- ✅ JSON-RPC batch balance checking (multicall.py)
- ✅ Dedup via in-memory sets (scanner_engine.py:74-75)
- ✅ Auto-sweeper integrated (scanner_engine.py:206-230)
- ✅ Leak scanner running hourly (run_scanner.py)
- ✅ Telegram alerts configured
- ✅ Endpoint rotation with health tracking

## Remaining Work

### 1. Shared httpx Client (HIGH IMPACT)
**File:** `src/modules/crypto/balance/scanner_engine.py`
- Create one shared `httpx.AsyncClient` for all workers (connection pool, max 20 connections)
- **Wiring steps:**
  - a) In `run()` at ~line 167: `self._client = httpx.AsyncClient(timeout=15)` before starting workers
  - b) In `_worker()`: pass `self._client` to `_check_balances(client=self._client)`
  - c) In `_check_balances()`: pass `client` to `check_balance()` at line 313 and `batch_check_balances()` at line 325
  - d) In `run()`: `await self._client.aclose()` after `asyncio.gather` completes
- `self._client` already declared at line 73 (currently unused) — reuse it
- `client` param already exists on checker.py:55, multicall.py:35 — just needs plumbing
- **Expected impact:** 2-3x throughput improvement (4.2 → 10-15/sec)

### ~~2. Add SOL Endpoint~~ ALREADY DONE
- SOL already has 3 endpoints: mainnet-beta, alchemy/demo, ankr (api_rotation.py:44-48)
- Verified: no action needed

### 3. Benchmark Derivation on VPS (LOW IMPACT)
**File:** `tests/benchmarks/benchmark_derivation.py`
- Verify derivation is ~1ms on VPS (not 150ms as originally assumed)
- If > 10ms, consider multiprocessing; if < 10ms, skip Phase 3

### 4. Phase 2: Bloom Filter for Dedup (FUTURE)
**File:** `src/modules/crypto/balance/bloom_filter.py` (new)
- Replace in-memory `_seen_addresses` set with space-efficient Bloom filter
- Purpose: dedup (prevent re-checking same address), NOT pre-filtering funded addresses
- Use `pybloom-live` (~300MB for all chains at 1% FP rate)
- **Only if** in-memory sets cause memory pressure in long-running scans

### 5. Phase 3: Multiprocessing (ONLY IF NEEDED)
**File:** `src/modules/crypto/balance/mp_deriver.py` (new)
- Only if single-process async can't sustain 50+/sec after Phase 1
- `multiprocessing.Pool(workers=4)` with Queue + run_in_executor bridge
- **Measure Phase 1 first** — multiprocessing may be unnecessary

## Acceptance Criteria
- [ ] Shared httpx client passed to all balance checks
- [x] SOL has 3 endpoints in registry (already satisfied)
- [ ] Throughput >= 10/sec on VPS (measured)
- [ ] All existing 649+ tests pass
- [ ] Graceful shutdown on SIGINT/SIGTERM

## ADR

### Decision
Focus on shared httpx client + endpoint expansion as the primary optimization path. Defer multiprocessing unless proven necessary.

### Drivers
- Derivation is ~1ms (not 150ms) — CPU is NOT the bottleneck
- Real bottleneck is per-call HTTP overhead + API rate limits
- Shared client eliminates TCP+TLS handshake per call

### Consequences
- Simplest possible optimization (no new architecture)
- If 10-15/sec is insufficient, revisit multiprocessing later

### Follow-ups
- [ ] Implement shared httpx client
- [ ] Add SOL endpoint
- [ ] Benchmark on VPS
- [ ] If < 50/sec, consider multiprocessing (Phase 3)
