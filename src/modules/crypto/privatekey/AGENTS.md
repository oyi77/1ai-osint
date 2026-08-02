<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# privatekey

## Purpose
Private key scanning and validation — detects leaked private keys in repos/leak data and validates key format. Does NOT check balances (see `../balance/` for balance checks).

## Key Files
| File | Description |
|------|-------------|
| `scanner.py` | Detects leaked private keys (githound subprocess + regex fallback); maps formats to severity via `detect_key_format()` |
| `checker.py` | Validates private key format (WIF/hex/base58/PEM) via `validate_key()` — format checks only, no balance queries |

## For AI Agents

### Working In This Directory
- Severity map (`_SEVERITY_MAP`): WIF / 32-byte hex / `0x` hex / PEM-private → CRITICAL; base58 / PEM-encrypted → HIGH
- Scanner tries githound subprocess first, falls back to embedded regex scanning
- Checker uses custom `_base58_decode` and per-format validators (`validate_wif`, `validate_hex_key`, `validate_base58_key`, `validate_pem_key`)
- Balance checks live in `../balance/`, not here

> Last updated: corrected scanner/checker descriptions (no balance checking); removed stale mnemonic/nacl notes (commit 8fa2bbf)

<!-- MANUAL: -->
