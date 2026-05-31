# Mission: Sweep Success

**Goal:** Make the crypto leak scanner reliably find and sweep funded wallets. Any non-zero amount of cryptocurrency must land in destination wallet `4FRKaVCCHzewoi8wekgXYGDh8Tq6GLJegwE18SDcePzZ`.

**Evaluator:** `/Users/paijo/1ai-osint/.omc/scripts/sweep-evaluator.sh 12`

**Success Criteria:**
- Destination wallet balance increases by any non-zero amount
- New incoming transaction appears in `getSignaturesForAddress`
- Sweep TX is confirmed on-chain (not just `sendTransaction` success)
- Source of swept funds is traceable to a leaked key

**Max Runtime:** 7200 seconds (2 hours)

**Context:**
- 8 leak sources scanning 24/7 on VPS (GitHub, Reddit, Twitter, paste, BitcoinTalk, DuckDuckGo, Telegram, GitLab)
- ~443+ leaks per scan cycle
- 1 confirmed sweep: 0.001364 SOL
- Key fixes applied: Solana derivation, sweeper init, skipPreflight=False, rent-exempt subtraction
- Common failures: InvalidAccountForFee (program-owned), InsufficientFundsForFee (dust), competition
