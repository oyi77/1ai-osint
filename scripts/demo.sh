#!/usr/bin/env bash
# demo.sh -- Demonstrates the full 1ai-osint workflow.
#
# Usage:
#   bash scripts/demo.sh [TARGET]
#
# TARGET defaults to "testuser123" (a sample username).
# Set environment variables for real API keys in .env before running.

set -euo pipefail

TARGET="${1:-testuser123}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "============================================"
echo "  1ai-osint Demo"
echo "============================================"
echo ""

# ------------------------------------------------------------------
# 1. Show version
# ------------------------------------------------------------------
echo "[1/7] Showing version..."
python -m src.cli version
echo ""

# ------------------------------------------------------------------
# 2. Scan with ALL modules (default output = json)
# ------------------------------------------------------------------
echo "[2/7] Running scan with all modules (json output)..."
echo "  Target: $TARGET"
echo "  -------------------------------------------------"
python -m src.cli scan "$TARGET" --module all --output json 2>/dev/null || true
echo ""
echo "  -------------------------------------------------"
echo ""

# ------------------------------------------------------------------
# 3. Scan with AI analysis enabled
# ------------------------------------------------------------------
echo "[3/7] Running scan with --ai flag..."
echo "  Target: $TARGET"
echo "  -------------------------------------------------"
python -m src.cli scan "$TARGET" --module data_leaks --ai --output json 2>/dev/null || true
echo ""
echo "  -------------------------------------------------"
echo ""

# ------------------------------------------------------------------
# 4. Scan with ZKIT identity tracking
# ------------------------------------------------------------------
echo "[4/7] Running scan with --zkit flag..."
echo "  Target: $TARGET"
echo "  -------------------------------------------------"
python -m src.cli scan "$TARGET" --module data_leaks --zkit --zkit_salt "demo-salt-2024" --output json 2>/dev/null || true
echo ""
echo "  -------------------------------------------------"
echo ""

# ------------------------------------------------------------------
# 5. SARIF output format
# ------------------------------------------------------------------
echo "[5/7] Running scan with SARIF output..."
echo "  Target: $TARGET"
echo "  -------------------------------------------------"
python -m src.cli scan "$TARGET" --module gitleaks --output sarif 2>/dev/null || true
echo ""
echo "  -------------------------------------------------"
echo ""

# ------------------------------------------------------------------
# 6. PDF output format
# ------------------------------------------------------------------
echo "[6/7] Running scan with PDF output..."
echo "  Target: $TARGET"
echo "  -------------------------------------------------"
PDF_OUT="/tmp/1ai-osint-demo-report.pdf"
python -m src.cli scan "$TARGET" --module data_leaks --output pdf > "$PDF_OUT" 2>/dev/null || true
if [ -f "$PDF_OUT" ] && [ -s "$PDF_OUT" ]; then
    echo "  PDF report written to: $PDF_OUT ($(wc -c < "$PDF_OUT") bytes)"
else
    echo "  PDF generation skipped (reportlab may not be installed)."
fi
echo ""
echo "  -------------------------------------------------"
echo ""

# ------------------------------------------------------------------
# 7. Individual module demos
# ------------------------------------------------------------------
echo "[7/7] Running individual module scans..."
for mod in gitleaks data_leaks people phone crypto_privatekey; do
    echo "  -- Module: $mod --"
    python -m src.cli scan "$TARGET" --module "$mod" --output json 2>/dev/null || true
    echo ""
done

echo "============================================"
echo "  Demo complete."
echo "============================================"
