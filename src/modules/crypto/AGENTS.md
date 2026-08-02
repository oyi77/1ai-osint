<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# crypto

## Purpose
ZKIT module for crypto-focused OSINT — leak finding across sources, multi-chain balance checking, wallet sweeping, key derivation, and mnemonic/privatekey randomization. One of several modules feeding findings into the ZKIT identity correlation engine.

## Key Files
| File | Description |
|------|-------------|
| `tx_tracer.py` | Blockchain transaction tracing — `BlockchainTxTracer`, registered as `crypto_tracer` |

> **Known limitation:** `tx_tracer.py` matches addresses against placeholder `KNOWN_EXCHANGES`/`KNOWN_MIXERS` entries (not real addresses) and its BTC trace self-queries (`from`/`to` = scanned address), so exchange/mixer attribution and risk scoring from it are unreliable. Findings now carry `attribution_unverified=True` / `attribution_verified=False` (`tx_tracer.py:115`/`:189`), `risk_reasoning` is prefixed `UNVERIFIED:` (`tx_tracer.py:162`/`:169`), and calls go through `RateLimiter` (30 rpm, burst 5, `tx_tracer.py:67`). The placeholder lists are intentionally kept.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `balance/` | Core crypto engine — scanning, checking, sweeping, derivation (see `balance/AGENTS.md`) |
| `leak_finder/` | Multi-source leak discovery with coordinator pattern (see `leak_finder/AGENTS.md`) |
| `passphrase/` | BIP-39 passphrase generation and checking (see `passphrase/AGENTS.md`) |
| `privatekey/` | Private key scanning and validation (see `privatekey/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- This is the most actively developed area — hot path code
- Multi-chain support: EVM, Solana, Bitcoin, Tron, and 10+ chains
- Async-first with endpoint rotation and rate limiting
- Sweep destinations configured per chain

### Common Patterns
- Chain definitions in `balance/chains.py`
- Provider profiles in `balance/provider_profiles.py`
- API rotation via `balance/api_rotation.py`

## Dependencies

### External
- web3.py — EVM chains
- solders — Solana
- bit — Bitcoin
- httpx — async HTTP

> Last updated: added `tx_tracer.py` and its known attribution limitation (commit 8fa2bbf)

<!-- MANUAL: -->
> Last updated: fix pass — tx_tracer output flagged UNVERIFIED/attribution_unverified (tx_tracer.py:115/162/169/189), RateLimiter(30 rpm, burst 5) wired (tx_tracer.py:67), placeholder lists kept
