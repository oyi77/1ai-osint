#!/bin/bash
# Evaluator for best-OSINT autoresearch mission
# Runs lint + tests, reports pass/fail with metrics

set -e

echo "=== Lint Check ==="
if ruff check src/ tests/ 2>&1; then
    echo "LINT: PASS"
    LINT_PASS=1
else
    echo "LINT: FAIL"
    LINT_PASS=0
fi

echo ""
echo "=== Unit Tests ==="
rm -f .coverage
TEST_OUTPUT=$(python -m pytest tests/unit/ -q --tb=line --no-header 2>&1)
echo "$TEST_OUTPUT"

# Extract pass/fail counts (macOS compatible)
PASSED=$(echo "$TEST_OUTPUT" | grep -o '[0-9]* passed' | grep -o '[0-9]*' || echo "0")
FAILED=$(echo "$TEST_OUTPUT" | grep -o '[0-9]* failed' | grep -o '[0-9]*' || echo "0")
COVERAGE=$(echo "$TEST_OUTPUT" | grep -o '[0-9]*\.[0-9]*%' | tail -1 | tr -d '%' || echo "0")

echo ""
echo "=== Summary ==="
echo "Lint: $([ $LINT_PASS -eq 1 ] && echo 'PASS' || echo 'FAIL')"
echo "Tests: $PASSED passed, $FAILED failed"
echo "Coverage: ${COVERAGE}%"

# Exit code: 0 if all pass, 1 otherwise
if [ $LINT_PASS -eq 1 ] && [ "$FAILED" = "0" ]; then
    echo "RESULT: PASS"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
