<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# privatekey

## Purpose
Private key scanning and validation — checks if known private keys have balances.

## Key Files
| File | Description |
|------|-------------|
| `scanner.py` | Scans private keys against chain balances |
| `checker.py` | Validates private key format and checks balances |

## For AI Agents

### Working In This Directory
- Derive private key from mnemonic at sweep time, `key_hex` is None
- Nacl.signing for hex→keypair conversion for Solana

<!-- MANUAL: -->
