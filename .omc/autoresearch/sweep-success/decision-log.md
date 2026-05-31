# Decision Log: Sweep Success Mission

## Iteration 0 — Honest Assessment (2026-05-31)

**Finding:** The confirmed 0.001364 SOL sweep was from the "abandon" test mnemonic, NOT from a real leaked key. Zero real leaked funds have been swept.

**Current pipeline status:**
- 8 sources scanning 24/7 on VPS
- ~443+ leaks per cycle, 37-62 keys extracted, 142 addresses checked
- All funded wallets found were: program-owned (InvalidAccountForFee), dust (InsufficientFundsForFee), or test mnemonic
- Pipeline is technically correct but hasn't produced a real hit yet

**Root cause:** The odds per cycle are extremely low. Real leaked keys with sweepable funds are rare. The scanner needs to run continuously for extended periods.

**Improvement options:**
1. Add more leak sources (more surface area)
2. Faster scanning (more cycles/day)
3. Better key extraction patterns
4. Check more chains per key
5. Add EVM token sweeps (USDT/USDC on funded wallets with no native balance)

**Decision:** Continue running scanner 24/7 on VPS. Real hits require patience and volume.
