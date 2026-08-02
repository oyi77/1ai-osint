#!/usr/bin/env bash
# audit_runner.sh — internal audit gate (Gap 1).
#
# Runs the full internal verification stack end-to-end and writes receipts
# under docs/evidence/audit/. Non-zero exit on any failure so CI and local
# runs fail loudly instead of quietly shipping unverified work.
#
#   lint      → ruff check src/ tests/            (make lint)
#   typecheck → mypy src/                         (make typecheck)
#   lint2     → ruff check scripts/               (not covered by make lint)
#   type2     → mypy scripts/                     (not covered by make typecheck)
#   secrets   → bandit src/ -lll                 (fail on HIGH findings)
#   tests     → full pytest suite (~2.6k tests)
#   soak      → 30s keyless soak                  (stability gate)
#   adv       → adversarial receipts (SSRF / auth fail-closed / hostile input)
#
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$PWD/.venv/bin:$PATH"

AUDIT_DIR="docs/evidence/audit"
mkdir -p "$AUDIT_DIR"
STAMP="$(date -u +%Y-%m-%d)"
SUMMARY="$AUDIT_DIR/summary_${STAMP}.txt"
PASS=1

note() { echo "[audit] $*" | tee -a "$SUMMARY"; }

: > "$SUMMARY"

run_step() {
    local label="$1"; shift
    note "== $label: $*"
    if "$@"; then
        note "   $label: OK"
    else
        note "   $label: FAILED (exit $?)"
        PASS=0
    fi
}

note "audit gate started: $(date -u -Iseconds)"

run_step "lint"        uv run make lint
run_step "typecheck"   uv run make typecheck
run_step "lint-scripts" uv run ruff check scripts/
run_step "type-scripts" uv run mypy scripts/

note "== secrets: bandit src/ -lll (fail on HIGH)"
BANDIT_OK=0
if uv run bandit -r src -lll -f json -o "$AUDIT_DIR/bandit_${STAMP}.json" >/dev/null 2>&1; then
    BANDIT_OK=1
elif command -v uvx >/dev/null 2>&1 && uvx bandit -r src -lll -f json -o "$AUDIT_DIR/bandit_${STAMP}.json" >/dev/null 2>&1; then
    BANDIT_OK=1
    note "   secrets: OK (uvx fallback)"
fi
if [ "$BANDIT_OK" -eq 1 ]; then
    note "   secrets: OK"
else
    note "   secrets: FAILED (bandit unavailable, crashed, or HIGH-severity finding)"
    PASS=0
fi

run_step "tests"       uv run pytest -q --tb=short
run_step "soak"        uv run python scripts/soak.py --duration 30 --json > "$AUDIT_DIR/soak_${STAMP}.json"
run_step "adversarial" uv run python scripts/adversarial_check.py --out "$AUDIT_DIR"

if [ "$PASS" -eq 1 ]; then
    echo "[audit] ALL CHECKS PASSED — receipts in $AUDIT_DIR" | tee -a "$SUMMARY"
    exit 0
else
    echo "[audit] AUDIT GATE FAILED — see $SUMMARY" | tee -a "$SUMMARY"
    exit 1
fi
