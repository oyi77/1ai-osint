# Scanner Performance Optimization Plan

## Current State
- **Throughput:** 4.2 mnemonics/sec
- **Bottlenecks:** BTC individual calls (0.5s/addr), derivation CPU-bound, single VPS
- **Coverage:** 5 chains (ETH/BSC/Polygon/BTC/SOL), 7 addresses per mnemonic
- **API:** Free public endpoints with rotation

## Target State
- **Throughput:** 50-100+ mnemonics/sec
- **Infrastructure:** Multi-VPS distributed scanning
- **Coverage:** 9+ chains, ERC-20/SPL token balances, more derivation paths
- **API:** Free APIs with aggressive rotation + endpoint pool expansion

---

## Phase 1: Throughput Optimization (Biggest Impact)

### 1.1 Remove BTC Delay Bottleneck
**Current:** 0.5s delay × 3 addresses = 1.5s per mnemonic
**Fix:** Add more BTC endpoints and reduce delay to 0.1s

**New BTC endpoints to add:**
- `mempool.space/api` (already have)
- `blockstream.info/api` (already have, but 429s)
- `blockchain.info/rawaddr/{addr}` (free, no key)
- `blockcypher.com/v1/btc/main/addrs/{addr}/balance` (free, 3 req/sec)
- `api.blockchair.com/bitcoin/dashboards/address/{addr}` (free, 30 req/min)

**Files:** `src/modules/crypto/balance/api_rotation.py`, `src/modules/crypto/balance/chains.py`

### 1.2 Optimize EVM Batch Checking
**Current:** JSON-RPC batch (1 request per chain per mnemonic)
**Fix:** Batch ALL mnemonics' addresses into fewer requests

**Approach:** Accumulate addresses from multiple mnemonics, send as one batch per chain every 0.1s.

**Files:** `src/modules/crypto/balance/multicall.py`, `src/modules/crypto/balance/scanner_engine.py`

### 1.3 Increase Worker Count
**Current:** 10 workers, 4.2/sec
**Target:** 50 workers with better rate limiting

**Files:** `run_scanner.py`, `src/modules/crypto/balance/scanner_engine.py`

---

## Phase 2: CPU Optimization

### 2.1 Multiprocessing Derivation
**Current:** Single-thread derivation (~244/sec), GIL-limited
**Fix:** Use `ProcessPoolExecutor` to bypass GIL

```python
from concurrent.futures import ProcessPoolExecutor
executor = ProcessPoolExecutor(max_workers=4)
loop.run_in_executor(executor, derive_from_mnemonic, mnemonic, chains)
```

**Expected:** 4-core VPS → ~1000/sec derivation throughput

**Files:** `src/modules/crypto/balance/scanner_engine.py`

### 2.2 Native PBKDF2 (Optional)
**Current:** Python's `hashlib.pbkdf2_hmac` (~244/sec)
**Fix:** Use `pycryptodome` C extension or `hashlib` with OpenSSL

```python
# Check if OpenSSL-accelerated PBKDF2 is available
import hashlib
# Python 3.10+ with OpenSSL: ~500-1000/sec
```

**Files:** `src/modules/crypto/balance/deriver.py`

---

## Phase 3: Coverage Expansion

### 3.1 More Chains
Add support for:
- **Avalanche (AVAX)** — EVM-compatible, public RPC: `api.avax.network/ext/bc/C/rpc`
- **Arbitrum (ARB)** — EVM-compatible, public RPC: `arb1.arbitrum.io/rpc`
- **Tron (TRX)** — Different API: `api.trongrid.io`
- **TON** — Different API: `toncenter.com/api/v2`
- **Dogecoin (DOGE)** — Similar to BTC: `dogechain.info/api`

**Files:** `src/modules/crypto/balance/chains.py`, `src/modules/crypto/balance/deriver.py`

### 3.2 ERC-20/SPL Token Balances
**EVM:** Call `balanceOf(address)` on popular token contracts
**SOL:** Use `getTokenAccountsByOwner` RPC method

**Approach:** Check top 10 tokens per chain (USDT, USDC, DAI, WETH, etc.)

**Files:** `src/modules/crypto/balance/checker.py`, `src/modules/crypto/balance/multicall.py`

### 3.3 More Derivation Paths
**Current:** BIP-44 (Legacy), BIP-49 (SegWit), BIP-84 (Native SegWit) for BTC
**Add:** Multiple account indices (0-4), change addresses (0-1)

**Files:** `src/modules/crypto/balance/deriver.py`

---

## Phase 4: Distributed Scanning

### 4.1 Multi-VPS Architecture
- **Coordinator:** Manages work distribution, dedup, alerting
- **Workers:** Multiple VPS instances scanning in parallel
- **Shared State:** Redis for dedup (seen mnemonics/addresses)

### 4.2 Work Distribution
- Each worker gets a unique seed range for mnemonic generation
- Workers report hits to coordinator via webhook
- Coordinator handles alerting and sweep

### 4.3 Shared Dedup
- Redis `SET` for seen mnemonics (TTL 24h)
- Redis `SET` for seen addresses (TTL 24h)
- Workers check Redis before scanning

**Files:** New `src/modules/crypto/balance/coordinator.py`, `src/modules/crypto/balance/worker.py`

---

## Phase 5: Leak Scanner Enhancement

### 5.1 More Sources
- **GitHub:** Search for `.env` files with mnemonic patterns
- **Pastebin:** Monitor recent pastes
- **Telegram:** Monitor public channels for leaked keys
- **Dork scanning:** Google dorks for exposed wallet files

### 5.2 Faster Verification
- Parallel verification of candidates
- Batch balance checking for leaked addresses

**Files:** `src/modules/crypto/balance/leak_scanner.py`

---

## Implementation Order

| Priority | Phase | Impact | Effort |
|----------|-------|--------|--------|
| 1 | Phase 1: Throughput | High | Medium |
| 2 | Phase 2: CPU Optimization | High | Medium |
| 3 | Phase 3: Coverage | Medium | High |
| 4 | Phase 4: Distributed | High | High |
| 5 | Phase 5: Leak Scanner | Low | Medium |

---

## Verification

1. Run benchmark: `python -m pytest tests/benchmarks/ -v -s`
2. Measure throughput: `python -c "import asyncio; ..."`
3. Test distributed: Deploy to 2+ VPS, verify coordination
4. Full test suite: `python -m pytest tests/ -q`
