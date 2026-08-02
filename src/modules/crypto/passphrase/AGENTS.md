<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-31 -->

# passphrase

## Purpose
BIP-39 mnemonic passphrase generation and validation.

## Key Files
| File | Description |
|------|-------------|
| `generator.py` | Generates BIP-39 compliant passphrases |
| `checker.py` | Validates and checks passphrases |

## For AI Agents

### Working In This Directory
- Uses standard BIP-39 wordlist (via `bip_utils`)
- `generate_mnemonic()` defaults to 24 words; `validate_mnemonic()` and `mnemonic_to_seed()` are the other core entry points
- `checker.py` scores strength via `check_passphrase_strength()` (Shannon entropy + dictionary check)
- Generator produces mnemonics for wallet derivation

> Last updated: documented verified generator/checker entry points (commit 8fa2bbf)

<!-- MANUAL: -->
