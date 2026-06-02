<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# crypto

## Purpose
ZKIT module for crypto-focused OSINT — leak finding across sources, multi-chain balance checking, wallet sweeping, key derivation, and mnemonic/privatekey randomization. One of several modules feeding findings into the ZKIT identity correlation engine.

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

<!-- MANUAL: -->
